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
 * Known-good defaults: lodash, react, express, axios, chalk
 * Known-bad: pass via --bad or use --from-ghsa (fetches npm advisories from GitHub)
 *
 * Feature keys align with ts/src/lib/mlDetection.ts FeatureVector and train.py FEATURE_KEYS.
 */

const KNOWN_GOOD = [
  'lodash',
  'react',
  'express',
  'axios',
  'chalk',
  'typescript',
  'jest',
  'webpack',
  'vue',
  'next',
];

/** All feature keys expected by train.py / serve.py */
const FEATURE_KEYS = [
  'daysDifference',
  'recentCommitCount',
  'scopePrivate',
  'suspiciousPatternsCount',
  'timelineAnomaly',
  'registryIsNpm',
  'authorCount',
  'totalCommitCount',
  'dominantAuthorShare',
  'commitPatternAnomaly',
  'branchCount',
  'recentCommitCount90d',
  'messageAnomalyScore',
  'diffAnomalyScore',
  'nlpSecurityScore',
  'nlpSuspiciousCount',
  'crossPackageAnomaly',
  'behavioralAnomaly',
  'reviewSecurityScore',
  'popularityScore',
  'trustScore',
];

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

/**
 * Compute timeline anomaly score (0-1). Aligns with ts/src/lib/timelineAnalysis.ts.
 */
function timelineAnomalyScore(daysSinceCreation, recentCommitCount = 0, hasScopeConflict = false) {
  let score = 0;
  if (daysSinceCreation <= 1) score += 0.5;
  else if (daysSinceCreation <= 7) score += 0.35;
  else if (daysSinceCreation <= 30) score += 0.2;
  if (recentCommitCount < 1) score += 0.2;
  else if (recentCommitCount < 5) score += 0.1;
  if (hasScopeConflict) score += 0.2;
  return Math.min(1, score);
}

/**
 * Build full feature vector aligned with FeatureVector in mlDetection.ts.
 * Uses npm metadata only; git/community/NLP require package path (--with-git not yet implemented).
 */
function buildFullFeatures(pkgName, data, _label) {
  const created = data?.time?.created ? new Date(data.time.created) : null;
  const now = new Date();
  const daysSinceCreation = created
    ? Math.abs(now - created) / (1000 * 60 * 60 * 24)
    : 365;
  const daysDifference = Math.min(365, daysSinceCreation);
  const isScoped = pkgName.startsWith('@');
  const scopePrivate = isScoped ? 1 : 0;
  const suspiciousPatterns = /^[a-z0-9]{32,}$/i.test(pkgName) ? 1 : 0;
  const timelineAnomaly = timelineAnomalyScore(daysSinceCreation, 0, scopePrivate === 1);

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

  return { features, label: _label };
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

async function main() {
  const args = process.argv.slice(2);
  let goodPkgs = KNOWN_GOOD;
  let badPkgs = [];
  let outFile = 'train.jsonl';
  let fromGhsa = false;
  let ghsaLimit = 100;
  let ghsaToken = process.env.GITHUB_TOKEN || null;

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
    }
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

  if (fromGhsa) {
    console.log('Fetching npm packages from GitHub Security Advisories...');
    try {
      const ghsaPkgs = await fetchGhsaNpmPackages({ limit: ghsaLimit, token: ghsaToken });
      console.log(`Found ${ghsaPkgs.length} unique npm packages with advisories`);
      for (const name of ghsaPkgs) {
        const data = await fetchNpmMetadata(name);
        const row = buildFullFeatures(name, data, 1);
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
    const row = buildFullFeatures(name, data, 0);
    addRow(row);
  }

  for (const name of badPkgs) {
    const data = await fetchNpmMetadata(name);
    const row = buildFullFeatures(name, data, 1);
    addRow(row);
  }

  const lines = rows.map((r) => JSON.stringify(r));
  fs.writeFileSync(outPath, lines.join('\n') + '\n');
  console.log(`Wrote ${lines.length} rows to ${outFile} (duplicates removed)`);
}

main().catch(console.error);
