#!/usr/bin/env node
/**
 * Export feature vectors for ML training.
 * Usage:
 *   node export-features.js --good lodash,react,express --out good.jsonl
 *   node export-features.js --bad package1,package2 --out bad.jsonl
 *   node export-features.js --good lodash,react --bad malicious-pkg --out train.jsonl
 *   node export-features.js --from-ghsa --out train.jsonl
 *   node export-features.js --from-ghsa --limit 200 --out bad.jsonl
 *
 * Git-enriched export (aligns commit/timeline features with ts/src/lib/mlDetection.ts):
 *   npm run build   # ensures ts/dist/lib exists; else js/lib is used
 *   node export-features.js --good lodash --with-git --package-root ~/clones --out train.jsonl
 *   node export-features.js --package-map ./paths.json --with-git --good lodash --out train.jsonl
 *   # paths.json: {"lodash":"/abs/path/to/lodash","@scope/pkg":"/abs/pkg"}
 *
 * Label lists from files (one package per line, # comments allowed):
 *   node export-features.js --good-file ./extra-good.txt --bad-file ./extra-bad.txt --out train.jsonl
 *
 * Known-good defaults: lodash, react, express, axios, chalk (from training-defaults.json)
 * Known-bad: pass via --bad or use --from-ghsa (fetches npm advisories from GitHub)
 *
 * Feature keys: ml-model/feature-keys.json (dependency); keep in sync with mlFeatureKeys.ts.
 */

const fsSync = require('fs');
const pathSync = require('path');
const { execSync } = require('child_process');
const featureManifest = JSON.parse(
  fsSync.readFileSync(pathSync.join(__dirname, 'feature-keys.json'), 'utf8')
);
const trainingDefaults = JSON.parse(
  fsSync.readFileSync(pathSync.join(__dirname, 'training-defaults.json'), 'utf8')
);
const KNOWN_GOOD = trainingDefaults.knownGoodPackages;
const FEATURE_KEYS = featureManifest.dependency;

function getGitHistorySync(packagePath) {
  try {
    const firstCommit = execSync('git log --reverse -1 --format="%H %ci" -- .', {
      cwd: packagePath,
      encoding: 'utf8',
      timeout: 10000,
    }).trim();

    if (!firstCommit) {
      return {
        commits: [],
        totalCommits: 0,
        hasGitHistory: false,
        firstCommitDate: null,
        recentCommitCount: 0,
      };
    }

    const dateStr = firstCommit.split(/\s+/).slice(1).join(' ');
    const firstCommitDate = new Date(dateStr);

    const recentCommitsStr = execSync('git log --format="%ci" --since="1 year ago" -- . | wc -l', {
      cwd: packagePath,
      encoding: 'utf8',
      timeout: 5000,
    }).trim();
    const recentCommitCount = parseInt(recentCommitsStr, 10) || 0;

    return {
      commits: [{ date: dateStr, message: '', author: '' }],
      totalCommits: 1,
      firstCommitDate,
      recentCommitCount,
      hasGitHistory: true,
    };
  } catch {
    return {
      commits: [],
      totalCommits: 0,
      hasGitHistory: false,
      firstCommitDate: null,
      recentCommitCount: 0,
    };
  }
}

/**
 * Load buildFeatureVector / analyzeCommitPatterns / analyzePackageName from built TS or mirrored JS.
 */
function loadMlBridge() {
  const repoRoot = pathSync.join(__dirname, '..');
  const libDirs = [
    pathSync.join(repoRoot, 'ts', 'dist', 'lib'),
    pathSync.join(repoRoot, 'js', 'lib'),
  ];
  let lastErr;
  for (const libDir of libDirs) {
    const mlPath = pathSync.join(libDir, 'mlDetection.js');
    const cpPath = pathSync.join(libDir, 'commitPatternAnalysis.js');
    const dcPath = pathSync.join(libDir, 'dependencyConfusion.js');
    if (!fsSync.existsSync(mlPath) || !fsSync.existsSync(cpPath) || !fsSync.existsSync(dcPath)) {
      continue;
    }
    try {
      return {
        buildFeatureVector: require(mlPath).buildFeatureVector,
        analyzeCommitPatterns: require(cpPath).analyzeCommitPatterns,
        analyzePackageName: require(dcPath).analyzePackageName,
        _source: libDir,
      };
    } catch (e) {
      lastErr = e;
    }
  }
  const msg = lastErr ? lastErr.message : 'missing mlDetection.js / commitPatternAnalysis.js / dependencyConfusion.js';
  throw new Error(
    `Could not load ML modules from ts/dist/lib or js/lib (${msg}). From repo root run: npm run build`
  );
}

function normalizeFeatureRow(fv) {
  const out = {};
  for (const k of FEATURE_KEYS) {
    const v = fv[k];
    out[k] = typeof v === 'number' && Number.isFinite(v) ? v : 0;
  }
  return out;
}

/**
 * Legacy npm-only vector (fallback if ML bridge cannot load).
 */
function buildFullFeaturesLegacy(pkgName, data, label) {
  const created = data?.time?.created ? new Date(data.time.created) : null;
  const now = new Date();
  const daysSinceCreation = created
    ? Math.abs(now - created) / (1000 * 60 * 60 * 24)
    : 365;
  const daysDifference = Math.min(365, daysSinceCreation);
  const isScoped = pkgName.startsWith('@');
  const scopePrivate = isScoped ? 1 : 0;
  const suspiciousPatterns = /^[a-z0-9]{32,}$/i.test(pkgName) ? 1 : 0;
  const recentCommitCount = 0;
  const hasScopeConflict = scopePrivate === 1;
  let timelineAnomaly = 0;
  if (daysSinceCreation <= 1) timelineAnomaly += 0.5;
  else if (daysSinceCreation <= 7) timelineAnomaly += 0.35;
  else if (daysSinceCreation <= 30) timelineAnomaly += 0.2;
  if (recentCommitCount < 1) timelineAnomaly += 0.2;
  else if (recentCommitCount < 5) timelineAnomaly += 0.1;
  if (hasScopeConflict) timelineAnomaly += 0.2;
  timelineAnomaly = Math.min(1, timelineAnomaly);

  const features = {
    daysDifference,
    recentCommitCount: 0,
    scopePrivate,
    suspiciousPatternsCount: suspiciousPatterns,
    timelineAnomaly,
    registryIsNpm: 1,
    authorCount: 0,
    totalCommitCount: 0,
    dominantAuthorShare: 0,
    commitPatternAnomaly: 0,
    branchCount: 0,
    recentCommitCount90d: 0,
    messageAnomalyScore: 0,
    diffAnomalyScore: 0,
    nlpSecurityScore: 0,
    nlpSuspiciousCount: 0,
    crossPackageAnomaly: 0,
    behavioralAnomaly: 0,
    reviewSecurityScore: 0.5,
    popularityScore: 0.5,
    trustScore: 0.5,
  };

  return {
    features: normalizeFeatureRow(features),
    label,
    exportedAt: new Date().toISOString(),
  };
}

function buildRowFromNpm(pkgName, data, label, bridge) {
  if (!bridge) {
    return buildFullFeaturesLegacy(pkgName, data, label);
  }
  const nameAnalysis = bridge.analyzePackageName(pkgName);
  const creationDate = data?.time?.created ? new Date(data.time.created) : null;
  const fv = bridge.buildFeatureVector({
    creationDate,
    registryCreated: creationDate,
    firstCommitDate: null,
    recentCommitCount: 0,
    scopeType: nameAnalysis.scopeType ?? null,
    suspiciousPatternsCount: nameAnalysis.suspiciousPatterns?.length ?? 0,
    registryName: 'npm',
    commitPatterns: null,
    nlpResult: null,
    crossPackageAnomaly: null,
    behavioralAnomaly: null,
    communityResult: null,
    trustScore: null,
  });
  return {
    features: normalizeFeatureRow(fv),
    label,
    exportedAt: new Date().toISOString(),
  };
}

function buildRowWithGit(pkgName, data, label, bridge, localPath) {
  const nameAnalysis = bridge.analyzePackageName(pkgName);
  const creationDate = data?.time?.created ? new Date(data.time.created) : null;
  const gitHistory = getGitHistorySync(localPath);
  const commitPatterns = bridge.analyzeCommitPatterns(localPath);
  const fv = bridge.buildFeatureVector({
    creationDate,
    registryCreated: creationDate,
    firstCommitDate: gitHistory.firstCommitDate,
    recentCommitCount: gitHistory.recentCommitCount ?? 0,
    scopeType: nameAnalysis.scopeType ?? null,
    suspiciousPatternsCount: nameAnalysis.suspiciousPatterns?.length ?? 0,
    registryName: 'npm',
    packagePath: localPath,
    commitPatterns,
    nlpResult: null,
    crossPackageAnomaly: null,
    behavioralAnomaly: null,
    communityResult: null,
    trustScore: null,
  });
  return {
    features: normalizeFeatureRow(fv),
    label,
    exportedAt: new Date().toISOString(),
  };
}

function resolveLocalPackagePath(pkgName, packageRoot, packageMap) {
  if (packageMap && typeof packageMap === 'object' && packageMap[pkgName]) {
    const p = packageMap[pkgName];
    return fsSync.existsSync(p) ? pathSync.resolve(p) : null;
  }
  if (!packageRoot) return null;
  const segments = pkgName.split('/');
  const candidate = pathSync.join(packageRoot, ...segments);
  return fsSync.existsSync(candidate) ? candidate : null;
}

function readPackageListFile(filePath) {
  if (!filePath || !fsSync.existsSync(filePath)) return [];
  const text = fsSync.readFileSync(filePath, 'utf8');
  return text
    .split(/\r?\n/)
    .map((line) => line.replace(/#.*$/, '').trim())
    .filter(Boolean);
}

/**
 * Fetch npm package names from GitHub Security Advisories (ecosystem=npm).
 * Supports reviewed vulnerabilities and malware advisories.
 */
async function fetchGhsaNpmPackages(options = {}) {
  const { limit = 100, includeMalware = true, token } = options;
  const headers = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  const seen = new Set();
  const packages = [];

  async function fetchPage(url) {
    const res = await fetch(url, { headers });
    if (!res.ok) {
      if (res.status === 403 || res.status === 429) {
        throw new Error(`GitHub API rate limit or forbidden. Set GITHUB_TOKEN for higher limits.`);
      }
      throw new Error(`GitHub API error: ${res.status} ${res.statusText}`);
    }
    const advisories = await res.json();
    const linkHeader = res.headers.get('link');
    return { advisories, linkHeader };
  }

  const types = includeMalware ? ['reviewed', 'malware'] : ['reviewed'];
  for (const type of types) {
    if (packages.length >= limit) break;
    let url = `https://api.github.com/advisories?ecosystem=npm&per_page=100&type=${type}`;
    let page = 0;
    const maxPages = 5;
    while (page < maxPages && packages.length < limit) {
      const { advisories, linkHeader } = await fetchPage(url);
      if (!Array.isArray(advisories) || advisories.length === 0) break;
      for (const adv of advisories) {
        if (adv.withdrawn_at) continue;
        const vulns = adv.vulnerabilities || [];
        for (const v of vulns) {
          const pkg = v?.package;
          if (pkg?.ecosystem === 'npm' && pkg?.name && !seen.has(pkg.name)) {
            seen.add(pkg.name);
            packages.push(pkg.name);
            if (packages.length >= limit) break;
          }
        }
        if (packages.length >= limit) break;
      }
      const nextMatch = linkHeader && linkHeader.match(/<([^>]+)>;\s*rel="next"/);
      if (!nextMatch) break;
      url = nextMatch[1];
      page++;
    }
  }

  return packages.slice(0, limit);
}

async function fetchNpmMetadata(packageName) {
  try {
    const res = await fetch(
      `https://registry.npmjs.org/${encodeURIComponent(packageName)}`
    );
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

async function main() {
  const args = process.argv.slice(2);
  let goodPkgs = [...KNOWN_GOOD];
  let badPkgs = [];
  let outFile = 'train.jsonl';
  let fromGhsa = false;
  let ghsaLimit = 100;
  let ghsaToken = process.env.GITHUB_TOKEN || null;
  let withGit = false;
  let packageRoot = null;
  let packageMapPath = null;
  let goodFile = null;
  let badFile = null;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--good' && args[i + 1]) {
      goodPkgs = args[++i].split(',').map((s) => s.trim()).filter(Boolean);
    } else if (args[i] === '--bad' && args[i + 1]) {
      badPkgs = args[++i].split(',').map((s) => s.trim()).filter(Boolean);
    } else if (args[i] === '--out' && args[i + 1]) {
      outFile = args[++i];
    } else if (args[i] === '--from-ghsa') {
      fromGhsa = true;
    } else if (args[i] === '--limit' && args[i + 1]) {
      ghsaLimit = parseInt(args[++i], 10) || 100;
    } else if (args[i] === '--token' && args[i + 1]) {
      ghsaToken = args[++i];
    } else if (args[i] === '--with-git') {
      withGit = true;
    } else if (args[i] === '--package-root' && args[i + 1]) {
      packageRoot = pathSync.resolve(args[++i]);
    } else if (args[i] === '--package-map' && args[i + 1]) {
      packageMapPath = pathSync.resolve(args[++i]);
    } else if (args[i] === '--good-file' && args[i + 1]) {
      goodFile = pathSync.resolve(args[++i]);
    } else if (args[i] === '--bad-file' && args[i + 1]) {
      badFile = pathSync.resolve(args[++i]);
    }
  }

  const extraGood = readPackageListFile(goodFile);
  const extraBad = readPackageListFile(badFile);
  if (extraGood.length) {
    goodPkgs = [...new Set([...goodPkgs, ...extraGood])];
  }
  if (extraBad.length) {
    badPkgs = [...new Set([...badPkgs, ...extraBad])];
  }

  let packageMap = null;
  if (packageMapPath) {
    try {
      packageMap = JSON.parse(fsSync.readFileSync(packageMapPath, 'utf8'));
    } catch (e) {
      console.error('Invalid --package-map JSON:', e.message);
      process.exitCode = 1;
      return;
    }
  }

  if (withGit && !packageRoot && !packageMap) {
    console.warn(
      'Warning: --with-git set but neither --package-root nor --package-map; using npm-only features for all rows.'
    );
  }

  let bridge = null;
  try {
    bridge = loadMlBridge();
    console.log('ML bridge loaded from', bridge._source);
  } catch (e) {
    console.warn('Warning:', e.message);
    console.warn('Falling back to legacy npm-only feature builder.');
  }

  const fs = await import('fs');
  const path = await import('path');
  const outPath = path.resolve(outFile);

  const seen = new Set();
  const rows = [];

  function addRow(row) {
    const key = JSON.stringify({ f: row.features, l: row.label });
    if (seen.has(key)) return;
    seen.add(key);
    rows.push(row);
  }

  if (fs.existsSync(outPath)) {
    const existing = fs.readFileSync(outPath, 'utf8').trim();
    if (existing) {
      for (const line of existing.split('\n')) {
        try {
          const row = JSON.parse(line);
          if (row && typeof row.label === 'number' && row.features) addRow(row);
        } catch {
          /* skip invalid lines */
        }
      }
    }
  }

  function makeRow(pkgName, data, label) {
    const localPath =
      withGit && bridge ? resolveLocalPackagePath(pkgName, packageRoot, packageMap) : null;
    if (withGit && bridge && localPath) {
      return buildRowWithGit(pkgName, data, label, bridge, localPath);
    }
    return buildRowFromNpm(pkgName, data, label, bridge);
  }

  let gitMiss = 0;
  if (fromGhsa) {
    console.log('Fetching npm packages from GitHub Security Advisories...');
    try {
      const ghsaPkgs = await fetchGhsaNpmPackages({ limit: ghsaLimit, token: ghsaToken });
      console.log(`Found ${ghsaPkgs.length} unique npm packages with advisories`);
      for (const name of ghsaPkgs) {
        const data = await fetchNpmMetadata(name);
        if (withGit && bridge) {
          const lp = resolveLocalPackagePath(name, packageRoot, packageMap);
          if (!lp) gitMiss++;
        }
        const row = makeRow(name, data, 1);
        addRow(row);
        await new Promise((r) => setTimeout(r, 100));
      }
    } catch (err) {
      console.error('GHSA fetch failed:', err.message);
      process.exitCode = 1;
    }
  }

  for (const name of goodPkgs) {
    const data = await fetchNpmMetadata(name);
    if (withGit && bridge) {
      const lp = resolveLocalPackagePath(name, packageRoot, packageMap);
      if (!lp) gitMiss++;
    }
    const row = makeRow(name, data, 0);
    addRow(row);
  }

  for (const name of badPkgs) {
    const data = await fetchNpmMetadata(name);
    if (withGit && bridge) {
      const lp = resolveLocalPackagePath(name, packageRoot, packageMap);
      if (!lp) gitMiss++;
    }
    const row = makeRow(name, data, 1);
    addRow(row);
  }

  if (withGit && bridge && gitMiss > 0 && (packageRoot || packageMap)) {
    console.log(
      `Note: ${gitMiss} package(s) had no matching local path under --package-root/--package-map; those rows used npm-only features.`
    );
  }

  const lines = rows.map((r) => JSON.stringify(r));
  fs.writeFileSync(outPath, lines.join('\n') + '\n');
  console.log(`Wrote ${lines.length} rows to ${outFile} (duplicates removed)`);
}

main().catch(console.error);
