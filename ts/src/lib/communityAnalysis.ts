/**
 * Community Analysis for package popularity and maintenance signals
 *
 * Fetches npm downloads, GitHub stars, and maintenance metadata.
 * Computes popularityScore, maintenanceScore, and reviewSecurityScore for ML pipeline.
 */

import axios from 'axios';
import { fetchPackageDocs, analyzeDocsNLP } from './nlpAnalysis';

export interface CommunityConfig {
  ENABLED?: boolean;
  GITHUB_TOKEN?: string | null;
  TIMEOUT_MS?: number;
  USE_DOWNLOADS?: boolean;
  USE_GITHUB_STARS?: boolean;
  USE_DEPENDENTS?: boolean;
}

export interface CommunityAnalysisResult {
  downloadCountWeekly: number;
  githubStars: number | null;
  dependentsCount: number | null;
  maintenanceScore: number;
  popularityScore: number;
  reviewSecurityScore: number;
}

const DEFAULT_CONFIG = {
  ENABLED: false,
  GITHUB_TOKEN: process.env['GITHUB_TOKEN'] || process.env['NULLVOID_GITHUB_TOKEN'] || null,
  TIMEOUT_MS: 10000,
  USE_DOWNLOADS: true,
  USE_GITHUB_STARS: true,
  USE_DEPENDENTS: false,
};

function parseGitHubRepoUrl(url: string): { owner: string; repo: string } | null {
  const patterns = [/github\.com[/:]([^/]+)\/([^/]+?)(?:\.git)?$/, /^([^/]+)\/([^/]+)$/];
  for (const pattern of patterns) {
    const m = url.match(pattern);
    if (m && m[1] && m[2]) return { owner: m[1], repo: m[2].replace(/\.git$/, '') };
  }
  return null;
}

/**
 * Fetch npm download count for last week
 */
export async function fetchNpmDownloads(
  packageName: string,
  config: Partial<CommunityConfig> = {}
): Promise<number> {
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

/**
 * Fetch GitHub stars for a repository URL
 */
export async function fetchGitHubStars(
  repoUrl: string,
  config: Partial<CommunityConfig> = {}
): Promise<number | null> {
  const parsed = parseGitHubRepoUrl(repoUrl);
  if (!parsed) return null;

  const { owner, repo } = parsed;
  const timeout = config.TIMEOUT_MS ?? DEFAULT_CONFIG.TIMEOUT_MS;

  try {
    const headers: Record<string, string> = {
      Accept: 'application/vnd.github.v3+json',
      'User-Agent': 'NullVoid-Security-Scanner/2.1.0',
    };
    if (config.GITHUB_TOKEN) {
      headers['Authorization'] = `Bearer ${config.GITHUB_TOKEN}`;
    }

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

/**
 * Fetch dependents count - npm has no official API; returns null
 * USE_DEPENDENTS can enable future third-party integration (e.g. npmdeps.com)
 */
export async function fetchDependentsCount(
  _packageName: string,
  config: Partial<CommunityConfig> = {}
): Promise<number | null> {
  if (!config.USE_DEPENDENTS) return null;
  return null;
}

/**
 * Compute maintenance score (0-1) from last publish date
 * Higher = more recently maintained
 */
function computeMaintenanceScore(timeCreated: string | null, timeModified: string | null): number {
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

/**
 * Compute popularity score (0-1) from downloads, stars, dependents
 * Uses log scale for downloads
 */
function computePopularityScore(
  downloads: number,
  stars: number | null,
  dependents: number | null
): number {
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

/**
 * Run full community analysis
 */
export async function runCommunityAnalysis(
  packageName: string,
  version: string = 'latest',
  config: Partial<CommunityConfig> & { COMMUNITY_CONFIG?: CommunityConfig } = {}
): Promise<CommunityAnalysisResult | null> {
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
    versionData = lastVer ? (data.versions?.[lastVer] ?? null) : null;
  }
  if (!versionData) return null;

  const timeCreated = data.time?.created ?? null;
  const timeObj = data.time as Record<string, string> | undefined;
  const resolvedVersion = versionData.version ?? version;
  const timeModified: string | null =
    timeObj?.['modified'] ??
    (resolvedVersion ? (timeObj?.[resolvedVersion] ?? null) : null) ??
    timeCreated;

  let githubStars: number | null = null;
  if (cfg.USE_GITHUB_STARS) {
    const repo = versionData.repository || data.repository;
    let repoUrl: string | undefined;
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
