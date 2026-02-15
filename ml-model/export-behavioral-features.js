#!/usr/bin/env node
/**
 * Export behavioral feature vectors for ML training.
 * Usage:
 *   node export-behavioral-features.js --good lodash,react,express --out train-behavioral.jsonl
 *   node export-behavioral-features.js --from-ghsa --limit 200 --out train-behavioral.jsonl
 *
 * Feature keys: scriptCount, scriptTotalLength, hasPostinstall, postinstallLength,
 *   preinstallLength, postuninstallLength, networkScriptCount, evalUsageCount,
 *   childProcessCount, fileSystemAccessCount, dependencyCount, devDependencyCount
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

const BEHAVIORAL_FEATURE_KEYS = [
  'scriptCount',
  'scriptTotalLength',
  'hasPostinstall',
  'postinstallLength',
  'preinstallLength',
  'postuninstallLength',
  'networkScriptCount',
  'evalUsageCount',
  'childProcessCount',
  'fileSystemAccessCount',
  'dependencyCount',
  'devDependencyCount',
];

function extractBehavioralCounts(scriptContent) {
  if (!scriptContent || typeof scriptContent !== 'string') {
    return { networkScriptCount: 0, evalUsageCount: 0, childProcessCount: 0, fileSystemAccessCount: 0 };
  }
  const network = (scriptContent.match(/fetch\s*\(|XMLHttpRequest|axios\.|request\s*\(|https?\.|curl|wget|download/gi) || []).length;
  const eval_ = (scriptContent.match(/eval\s*\(|Function\s*\(|new\s+Function/gi) || []).length;
  const childProcess = (scriptContent.match(/child_process|exec\s*\(|spawn\s*\(|execSync|spawnSync/gi) || []).length;
  const fs = (scriptContent.match(/require\s*\(\s*['"]fs['"]|fs\.|readFile|writeFile|unlink|mkdir|rmdir|chmod/gi) || []).length;
  return { networkScriptCount: network, evalUsageCount: eval_, childProcessCount: childProcess, fileSystemAccessCount: fs };
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

function buildBehavioralFeatures(pkgName, data, label) {
  const versions = data?.versions || {};
  const latest = data?.['dist-tags']?.latest;
  const pkg = latest ? versions[latest] : versions[Object.keys(versions).pop()];
  const scripts = (pkg?.scripts || {});
  const scriptKeys = Object.keys(scripts);
  const postinstall = scripts.postinstall ?? scripts.install;
  const preinstall = scripts.preinstall;
  const postuninstall = scripts.postuninstall;
  const allScriptContent = Object.values(scripts).join('\n');
  const counts = extractBehavioralCounts(allScriptContent);

  const deps = pkg?.dependencies || {};
  const devDeps = pkg?.devDependencies || {};

  const features = {
    scriptCount: scriptKeys.length,
    scriptTotalLength: scriptKeys.reduce((s, k) => s + (scripts[k] || '').length, 0),
    hasPostinstall: postinstall ? 1 : 0,
    postinstallLength: postinstall ? postinstall.length : 0,
    preinstallLength: preinstall ? preinstall.length : 0,
    postuninstallLength: postuninstall ? postuninstall.length : 0,
    networkScriptCount: counts.networkScriptCount,
    evalUsageCount: counts.evalUsageCount,
    childProcessCount: counts.childProcessCount,
    fileSystemAccessCount: counts.fileSystemAccessCount,
    dependencyCount: Object.keys(deps).length,
    devDependencyCount: Object.keys(devDeps).length,
  };

  return { features, label };
}

async function fetchGhsaNpmPackages(options = {}) {
  const { limit = 100, token } = options;
  const headers = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  const seen = new Set();
  const packages = [];

  let url = `https://api.github.com/advisories?ecosystem=npm&per_page=100&type=reviewed`;
  let page = 0;
  const maxPages = 5;

  while (page < maxPages && packages.length < limit) {
    const res = await fetch(url, { headers });
    if (!res.ok) {
      if (res.status === 403 || res.status === 429) {
        throw new Error('GitHub API rate limit. Set GITHUB_TOKEN for higher limits.');
      }
      throw new Error(`GitHub API error: ${res.status}`);
    }
    const advisories = await res.json();
    for (const adv of advisories || []) {
      if (adv.withdrawn_at) continue;
      for (const v of adv.vulnerabilities || []) {
        const pkg = v?.package;
        if (pkg?.ecosystem === 'npm' && pkg?.name && !seen.has(pkg.name)) {
          seen.add(pkg.name);
          packages.push(pkg.name);
          if (packages.length >= limit) break;
        }
      }
      if (packages.length >= limit) break;
    }
    const linkHeader = res.headers.get('link');
    const nextMatch = linkHeader && linkHeader.match(/<([^>]+)>;\s*rel="next"/);
    if (!nextMatch) break;
    url = nextMatch[1];
    page++;
  }

  return packages.slice(0, limit);
}

async function main() {
  const args = process.argv.slice(2);
  let goodPkgs = KNOWN_GOOD;
  let badPkgs = [];
  let outFile = 'train-behavioral.jsonl';
  let fromGhsa = false;
  let ghsaLimit = 100;
  const ghsaToken = process.env.GITHUB_TOKEN || null;

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
          /* skip */
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
        const row = buildBehavioralFeatures(name, data, 1);
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
    const row = buildBehavioralFeatures(name, data, 0);
    addRow(row);
  }

  for (const name of badPkgs) {
    const data = await fetchNpmMetadata(name);
    const row = buildBehavioralFeatures(name, data, 1);
    addRow(row);
  }

  const lines = rows.map((r) => JSON.stringify(r));
  fs.writeFileSync(outPath, lines.join('\n') + '\n');
  console.log(`Wrote ${lines.length} rows to ${outFile} (duplicates removed)`);
}

main().catch(console.error);
