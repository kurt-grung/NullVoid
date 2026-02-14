/**
 * Community Analysis for package popularity and maintenance signals
 *
 * Fetches npm downloads, GitHub stars, and maintenance metadata.
 * Computes popularityScore, maintenanceScore, and reviewSecurityScore for ML pipeline.
 */

const axios = require('axios');
const { fetchPackageDocs, analyzeDocsNLP } = require('./nlpAnalysis');

const DEFAULT_CONFIG = {
  ENABLED: false,
  GITHUB_TOKEN: process.env.GITHUB_TOKEN || process.env.NULLVOID_GITHUB_TOKEN || null,
  TIMEOUT_MS: 10000,
  USE_DOWNLOADS: true,
  USE_GITHUB_STARS: true,
  USE_DEPENDENTS: false,
};

function parseGitHubRepoUrl(url) {
  const m = url.match(/github\.com[/:]([^/]+)\/([^/]+?)(?:\.git)?$/);
  if (m) return { owner: m[1], repo: m[2].replace(/\.git$/, '') };
  return null;
}

async function fetchNpmDownloads(packageName, config = {}) {
  const timeout = config.TIMEOUT_MS ?? DEFAULT_CONFIG.TIMEOUT_MS;
  try {
    const url = `https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(packageName)}`;
    const res = await axios.get(url, {
      timeout,
      headers: { 'User-Agent': 'NullVoid-Security-Scanner/2.1.0' },
      validateStatus: (s) => s === 200,
    });
    const count = res.data?.downloads;
    return typeof count === 'number' ? count : 0;
  } catch {
    return 0;
  }
}

async function fetchGitHubStars(repoUrl, config = {}) {
  const parsed = parseGitHubRepoUrl(repoUrl);
  if (!parsed) return null;

  const { owner, repo } = parsed;
  const timeout = config.TIMEOUT_MS ?? DEFAULT_CONFIG.TIMEOUT_MS;

  try {
    const headers = {
      Accept: 'application/vnd.github.v3+json',
      'User-Agent': 'NullVoid-Security-Scanner/2.1.0',
    };
    if (config.GITHUB_TOKEN) headers['Authorization'] = `Bearer ${config.GITHUB_TOKEN}`;

    const res = await axios.get(`https://api.github.com/repos/${owner}/${repo}`, {
      headers,
      timeout,
      validateStatus: (s) => s === 200,
    });
    const stars = res.data?.stargazers_count;
    return typeof stars === 'number' ? stars : null;
  } catch {
    return null;
  }
}

async function fetchDependentsCount(_packageName, config = {}) {
  if (!config.USE_DEPENDENTS) return null;
  return null;
}

function computeMaintenanceScore(timeCreated, timeModified) {
  const modified = timeModified ? new Date(timeModified).getTime() : null;
  const created = timeCreated ? new Date(timeCreated).getTime() : null;
  const ref = modified ?? created;
  if (!ref) return 0.5;

  const now = Date.now();
  const daysSinceUpdate = (now - ref) / (24 * 60 * 60 * 1000);

  if (daysSinceUpdate <= 7) return 1;
  if (daysSinceUpdate <= 30) return 0.9;
  if (daysSinceUpdate <= 90) return 0.7;
  if (daysSinceUpdate <= 180) return 0.5;
  if (daysSinceUpdate <= 365) return 0.3;
  return 0.1;
}

function computePopularityScore(downloads, stars, dependents) {
  const logDownloads = downloads > 0 ? Math.log10(downloads + 1) : 0;
  const downloadScore = Math.min(1, logDownloads / 6);
  const starScore = stars != null ? Math.min(1, stars / 10000) : 0.5;
  const depScore = dependents != null ? Math.min(1, dependents / 100) : 0.5;

  const weights = { downloads: 0.5, stars: 0.3, dependents: 0.2 };
  let total = downloadScore * weights.downloads;
  total += starScore * weights.stars;
  total += depScore * weights.dependents;
  return Math.min(1, total);
}

async function runCommunityAnalysis(packageName, version = 'latest', config = {}) {
  const sub = config.COMMUNITY_CONFIG || config;
  const cfg = { ...DEFAULT_CONFIG, ...sub, ...config };
  if (!cfg.ENABLED) return null;

  const timeout = cfg.TIMEOUT_MS ?? DEFAULT_CONFIG.TIMEOUT_MS;

  const [registryRes, downloads, docs] = await Promise.all([
    axios
      .get(`https://registry.npmjs.org/${encodeURIComponent(packageName)}`, {
        timeout,
        headers: { 'User-Agent': 'NullVoid-Security-Scanner/2.1.0' },
        validateStatus: (s) => s === 200,
      })
      .catch(() => ({ data: null })),
    cfg.USE_DOWNLOADS ? fetchNpmDownloads(packageName, cfg) : Promise.resolve(0),
    fetchPackageDocs(packageName, version, { TIMEOUT_MS: timeout }),
  ]);

  const data = registryRes?.data;
  if (!data || typeof data !== 'object') return null;

  let versionData = data.versions?.[version];
  if (!versionData && version === 'latest') {
    const latestTag = data['dist-tags']?.latest;
    versionData = latestTag ? data.versions?.[latestTag] : null;
  }
  if (!versionData) {
    const versions = Object.keys(data.versions || {});
    const lastVer = versions[versions.length - 1];
    versionData = lastVer ? data.versions?.[lastVer] : null;
  }
  if (!versionData) return null;

  const timeCreated = data.time?.created ?? null;
  const timeObj = data.time;
  const resolvedVersion = versionData.version ?? version;
  let timeModified = timeObj?.modified ?? null;
  if (!timeModified && resolvedVersion && timeObj?.[resolvedVersion]) {
    timeModified = timeObj[resolvedVersion];
  }
  if (!timeModified) timeModified = timeCreated;

  let githubStars = null;
  if (cfg.USE_GITHUB_STARS) {
    const repo = versionData.repository || data.repository;
    let repoUrl;
    if (repo) {
      repoUrl = typeof repo === 'string' ? repo : repo?.url;
      if (repoUrl) repoUrl = repoUrl.replace(/^git\+/, '').replace(/\.git$/, '');
    }
    if (repoUrl && repoUrl.includes('github.com')) {
      githubStars = await fetchGitHubStars(repoUrl, cfg);
    }
  }

  const dependentsCount = await fetchDependentsCount(packageName, cfg);

  const maintenanceScore = computeMaintenanceScore(timeCreated, timeModified);
  const popularityScore = computePopularityScore(downloads, githubStars, dependentsCount);

  let reviewSecurityScore = 0.5;
  if (docs && (docs.readme || docs.description)) {
    const nlpResult = analyzeDocsNLP({ readme: docs.readme, description: docs.description });
    reviewSecurityScore = 1 - nlpResult.nlpSecurityScore;
  }

  return {
    downloadCountWeekly: downloads,
    githubStars,
    dependentsCount,
    maintenanceScore,
    popularityScore,
    reviewSecurityScore,
  };
}

module.exports = {
  runCommunityAnalysis,
  fetchNpmDownloads,
  fetchGitHubStars,
  fetchDependentsCount,
};
