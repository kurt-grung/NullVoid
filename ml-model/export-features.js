#!/usr/bin/env node
/**
 * Export feature vectors for ML training.
 * Usage:
 *   node export-features.js --good lodash,react,express --out good.jsonl
 *   node export-features.js --bad package1,package2 --out bad.jsonl
 *   node export-features.js --good lodash,react --bad malicious-pkg --out train.jsonl
 *   node export-features.js --from-ghsa --out train.jsonl            # GHSA *malware* advisories = label 1
 *   node export-features.js --from-ghsa --limit 2000 --good-file benign-packages.txt --out train.jsonl
 *   node export-features.js --from-ghsa --ghsa-cache .cache/ghsa-malware.json ...   # reuse a saved advisory list
 *   --snapshot-ages 2,10,30 | --no-snapshots   # early-life snapshots of benign packages (see below)
 *   --max-malware-age-days 180                 # drop advisories for long-established packages (compromised maintainers)
 *
 * Labels are ground truth only: GHSA advisories of type "malware" are 1, the
 * reviewed benign list (ml-model/benign-packages.txt, popular packages with no
 * malware advisory) is 0. Vulnerability advisories ("reviewed") are NOT
 * malware and are excluded unless --include-vulns is passed. Never label from
 * the scanner's own output.
 *
 * Each row carries `name`, `time` (first publish, ISO) and `source` so train.py
 * can do a time-based held-out split and the dataset is auditable.
 *
 * Git-enriched export (aligns commit/timeline features with ts/src/lib/mlDetection.ts):
 *   npm run build   # ensures ts/dist/lib exists
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
  const libDirs = [pathSync.join(repoRoot, 'ts', 'dist', 'lib')];
  let lastErr;
  for (const libDir of libDirs) {
    const mlPath = pathSync.join(libDir, 'mlDetection.js');
    const cpPath = pathSync.join(libDir, 'commitPatternAnalysis.js');
    const dcPath = pathSync.join(libDir, 'dependencyConfusion.js');
    const phPath = pathSync.join(libDir, 'publishHistory.js');
    if (
      !fsSync.existsSync(mlPath) ||
      !fsSync.existsSync(cpPath) ||
      !fsSync.existsSync(dcPath) ||
      !fsSync.existsSync(phPath)
    ) {
      continue;
    }
    try {
      return {
        buildFeatureVector: require(mlPath).buildFeatureVector,
        analyzeCommitPatterns: require(cpPath).analyzeCommitPatterns,
        analyzePackageName: require(dcPath).analyzePackageName,
        publishHistoryFeatures: require(phPath).publishHistoryFeatures,
        publishTimestamps: require(phPath).publishTimestamps,
        _source: libDir,
      };
    } catch (e) {
      lastErr = e;
    }
  }
  const msg = lastErr
    ? lastErr.message
    : 'missing mlDetection.js / commitPatternAnalysis.js / dependencyConfusion.js';
  throw new Error(
    `Could not load ML modules from ts/dist/lib (${msg}). From repo root run: npm run build`
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
  const daysSinceCreation = created ? Math.abs(now - created) / (1000 * 60 * 60 * 24) : 365;
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

/**
 * First real publish timestamp (placeholder versions excluded). The registry's
 * `time.created` is the holding package's date once npm has taken a package
 * down, so it cannot be used for malware rows.
 */
function firstPublishDate(data, bridge) {
  const stamps = bridge ? bridge.publishTimestamps(data?.time) : [];
  if (stamps.length) return stamps[0];
  return data?.time?.created ? new Date(data.time.created) : null;
}

function rowEnvelope(pkgName, data, label, bridge, meta) {
  const first = firstPublishDate(data, bridge);
  return {
    label,
    name: pkgName,
    time: first ? first.toISOString() : null,
    reference: meta.reference ? new Date(meta.reference).toISOString() : null,
    source: meta.source,
    advisory: meta.advisory ?? undefined,
    exportedAt: new Date().toISOString(),
  };
}

function buildRowFromNpm(pkgName, data, label, bridge, meta = { source: 'manual' }) {
  if (!bridge) {
    return {
      ...buildFullFeaturesLegacy(pkgName, data, label),
      ...rowEnvelope(pkgName, data, label, null, meta),
    };
  }
  const nameAnalysis = bridge.analyzePackageName(pkgName);
  const creationDate = firstPublishDate(data, bridge);
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
    publishHistory: bridge.publishHistoryFeatures(pkgName, data?.time, meta.reference ?? null),
  });
  return { features: normalizeFeatureRow(fv), ...rowEnvelope(pkgName, data, label, bridge, meta) };
}

function buildRowWithGit(pkgName, data, label, bridge, localPath, meta = { source: 'manual' }) {
  const nameAnalysis = bridge.analyzePackageName(pkgName);
  const creationDate = firstPublishDate(data, bridge);
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
    publishHistory: bridge.publishHistoryFeatures(pkgName, data?.time, meta.reference ?? null),
  });
  return { features: normalizeFeatureRow(fv), ...rowEnvelope(pkgName, data, label, bridge, meta) };
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
 * Fetch npm packages from GitHub Security Advisories.
 *
 * Returns [{ name, ghsaId, publishedAt }]. Only `type=malware` advisories are
 * malware; `type=reviewed` are vulnerabilities in otherwise legitimate packages
 * and are excluded unless includeVulns is set.
 */
async function fetchGhsaNpmPackages(options = {}) {
  const { limit = 100, includeVulns = false, token } = options;
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

  const types = includeVulns ? ['malware', 'reviewed'] : ['malware'];
  for (const type of types) {
    if (packages.length >= limit) break;
    let url = `https://api.github.com/advisories?ecosystem=npm&per_page=100&type=${type}`;
    let page = 0;
    const maxPages = Math.max(5, Math.ceil(limit / 100) + 2);
    while (page < maxPages && packages.length < limit) {
      const { advisories, linkHeader } = await fetchPage(url);
      if (!Array.isArray(advisories) || advisories.length === 0) break;
      for (const adv of advisories) {
        if (adv.withdrawn_at) continue;
        for (const v of adv.vulnerabilities || []) {
          const pkg = v?.package;
          if (pkg?.ecosystem === 'npm' && pkg?.name && !seen.has(pkg.name)) {
            seen.add(pkg.name);
            packages.push({
              name: pkg.name,
              ghsaId: adv.ghsa_id,
              publishedAt: adv.published_at || adv.updated_at || null,
              source: type === 'malware' ? 'ghsa-malware' : 'ghsa-vulnerability',
            });
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

/** Run `fn` over `items` with at most `concurrency` in flight, preserving order. */
async function mapPool(items, concurrency, fn) {
  const results = new Array(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i], i);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, worker));
  return results;
}

async function fetchNpmMetadata(packageName) {
  try {
    const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(packageName)}`);
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
  let includeVulns = false;
  let overwrite = false;
  let ghsaCache = null;
  let snapshotAges = [2, 10, 30];
  let maxMalwareAgeDays = 180;
  const registryDocs = new Map();
  let concurrency = 8;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--good' && args[i + 1]) {
      goodPkgs = args[++i]
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
    } else if (args[i] === '--bad' && args[i + 1]) {
      badPkgs = args[++i]
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
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
    } else if (args[i] === '--include-vulns') {
      includeVulns = true;
    } else if (args[i] === '--snapshot-ages' && args[i + 1]) {
      snapshotAges = args[++i]
        .split(',')
        .map((v) => parseInt(v.trim(), 10))
        .filter((v) => Number.isFinite(v) && v > 0);
    } else if (args[i] === '--no-snapshots') {
      snapshotAges = [];
    } else if (args[i] === '--max-malware-age-days' && args[i + 1]) {
      maxMalwareAgeDays = parseInt(args[++i], 10);
      if (!Number.isFinite(maxMalwareAgeDays) || maxMalwareAgeDays <= 0)
        maxMalwareAgeDays = Infinity;
    } else if (args[i] === '--ghsa-cache' && args[i + 1]) {
      ghsaCache = pathSync.resolve(args[++i]);
    } else if (args[i] === '--overwrite') {
      overwrite = true;
    } else if (args[i] === '--concurrency' && args[i + 1]) {
      concurrency = Math.max(1, parseInt(args[++i], 10) || 8);
    }
  }
  if (includeVulns) {
    console.warn(
      'Warning: --include-vulns labels packages with *vulnerability* advisories as malicious. They are not; use only for experiments.'
    );
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

  const fs = fsSync;
  const outPath = pathSync.resolve(outFile);

  const seenNames = new Set();
  const seenVectors = new Set();
  const rows = [];
  const skipped = { noRegistry: 0, duplicate: 0, compromisedExisting: 0 };

  function addRow(row) {
    if (row.name) {
      if (seenNames.has(row.name)) {
        skipped.duplicate++;
        return;
      }
      seenNames.add(row.name);
    }
    const key = JSON.stringify({ f: row.features, l: row.label });
    if (seenVectors.has(key)) {
      skipped.duplicate++;
      return;
    }
    seenVectors.add(key);
    rows.push(row);
  }

  if (!overwrite && fs.existsSync(outPath)) {
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
      console.log(
        `Loaded ${rows.length} existing rows from ${outFile} (pass --overwrite to start fresh)`
      );
    }
  }

  function makeRow(pkgName, data, label, meta) {
    const localPath =
      withGit && bridge ? resolveLocalPackagePath(pkgName, packageRoot, packageMap) : null;
    if (withGit && bridge && localPath) {
      return buildRowWithGit(pkgName, data, label, bridge, localPath, meta);
    }
    return buildRowFromNpm(pkgName, data, label, bridge, meta);
  }

  let gitMiss = 0;
  async function exportBatch(entries, label, defaultSource) {
    const built = await mapPool(entries, concurrency, async (entry) => {
      const name = typeof entry === 'string' ? entry : entry.name;
      const data = await fetchNpmMetadata(name);
      if (!data || !data.time) {
        skipped.noRegistry++;
        return null;
      }
      if (label === 0) registryDocs.set(name, { time: data.time });
      if (withGit && bridge && !resolveLocalPackagePath(name, packageRoot, packageMap)) gitMiss++;
      const meta =
        typeof entry === 'string'
          ? { source: defaultSource, reference: null }
          : {
              source: entry.source || defaultSource,
              reference: entry.publishedAt || null,
              advisory: entry.ghsaId,
            };
      return makeRow(name, data, label, meta);
    });
    let added = 0;
    for (const row of built) {
      if (!row) continue;
      const before = rows.length;
      addRow(row);
      if (rows.length > before) added++;
    }
    return added;
  }

  const malwareNames = new Set();
  if (fromGhsa) {
    console.log('Fetching npm malware advisories from GitHub Security Advisories...');
    try {
      let ghsaPkgs;
      if (ghsaCache && fsSync.existsSync(ghsaCache)) {
        ghsaPkgs = JSON.parse(fsSync.readFileSync(ghsaCache, 'utf8')).slice(0, ghsaLimit);
        console.log(`Using cached advisory list ${ghsaCache}`);
      } else {
        ghsaPkgs = await fetchGhsaNpmPackages({ limit: ghsaLimit, token: ghsaToken, includeVulns });
        if (ghsaCache) fsSync.writeFileSync(ghsaCache, JSON.stringify(ghsaPkgs, null, 1));
      }
      for (const p of ghsaPkgs) malwareNames.add(p.name);
      console.log(`Found ${ghsaPkgs.length} unique npm packages with advisories`);
      const added = await exportBatch(ghsaPkgs, 1, 'ghsa-malware');
      console.log(`  label 1: ${added} rows`);
      // The dependency model describes a package by its publish history. A
      // legitimate package whose maintainer account was compromised years after
      // its first release has a benign publish history by construction; those
      // advisories are a code-level problem (behavioral model / scanner), not a
      // registry-metadata one, and keeping them as positives only teaches the
      // model that old, busy packages are malware. They are counted and dropped.
      if (Number.isFinite(maxMalwareAgeDays)) {
        const before = rows.length;
        const kept = rows.filter(
          (r) =>
            r.label !== 1 ||
            !r.features ||
            (r.features.ageAtReferenceDays ?? 0) <= maxMalwareAgeDays
        );
        skipped.compromisedExisting = before - kept.length;
        rows.length = 0;
        rows.push(...kept);
        console.log(
          `  label 1: dropped ${skipped.compromisedExisting} advisories for packages first published > ${maxMalwareAgeDays} days before the advisory (compromised existing packages; out of scope for the publish-history model)`
        );
      }
    } catch (err) {
      console.error('GHSA fetch failed:', err.message);
      process.exitCode = 1;
    }
  }

  // A package with a malware advisory can never be in the benign class.
  const cleanGood = goodPkgs.filter((name) => !malwareNames.has(name));
  if (cleanGood.length !== goodPkgs.length) {
    console.log(
      `Dropped ${goodPkgs.length - cleanGood.length} benign candidate(s) that have a malware advisory`
    );
  }
  const goodAdded = await exportBatch(cleanGood, 0, goodFile ? 'benign-list' : 'known-good');
  console.log(`  label 0: ${goodAdded} rows`);

  // Early-life snapshots of benign packages. Every malware row is a young
  // package (it was caught days after publish); without benign rows of the same
  // age the model would learn "new package = malware". A popular package at
  // age 3 days with two versions was benign then too, so each benign package
  // also contributes rows describing it at a few points in its first weeks.
  if (snapshotAges.length > 0 && bridge) {
    let snapAdded = 0;
    for (const row of rows.filter(
      (r) => r.label === 0 && r.time && !r.source.endsWith('-snapshot')
    )) {
      const data = registryDocs.get(row.name);
      if (!data) continue;
      const first = new Date(row.time);
      for (const days of snapshotAges) {
        const reference = new Date(first.getTime() + days * 24 * 60 * 60 * 1000);
        if (reference.getTime() > Date.now()) continue;
        const snap = buildRowFromNpm(row.name, data, 0, bridge, {
          source: `${row.source}-snapshot`,
          reference,
        });
        snap.name = `${row.name}@+${days}d`;
        const before = rows.length;
        addRow(snap);
        if (rows.length > before) snapAdded++;
      }
    }
    console.log(
      `  label 0 (early-life snapshots at ${snapshotAges.join('/')} days): ${snapAdded} rows`
    );
  }

  if (badPkgs.length) {
    const badAdded = await exportBatch(badPkgs, 1, 'manual-malicious');
    console.log(`  label 1 (manual): ${badAdded} rows`);
  }

  if (withGit && bridge && gitMiss > 0 && (packageRoot || packageMap)) {
    console.log(
      `Note: ${gitMiss} package(s) had no matching local path under --package-root/--package-map; those rows used npm-only features.`
    );
  }

  const lines = rows.map((r) => JSON.stringify(r));
  fs.writeFileSync(outPath, lines.join('\n') + '\n');
  const pos = rows.filter((r) => r.label === 1).length;
  console.log(
    `Wrote ${lines.length} rows to ${outFile} (${pos} malicious / ${lines.length - pos} benign; skipped ${skipped.noRegistry} with no registry document, ${skipped.duplicate} duplicates)`
  );
}

main().catch(console.error);
