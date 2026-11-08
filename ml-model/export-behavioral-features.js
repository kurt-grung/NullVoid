#!/usr/bin/env node
/**
 * Export behavioral feature vectors (package.json scripts / dependencies) for ML training.
 *
 * Usage:
 *   npm run build   # the feature builder lives in ts/dist/lib/behavioralFeatures.js
 *   node export-behavioral-features.js --overwrite --from-ghsa --good-file benign-packages.txt --out train-behavioral.jsonl
 *   node export-behavioral-features.js --from-ghsa --ghsa-cache .cache/ghsa-malware.json ...
 *   node export-behavioral-features.js --good lodash,react --bad some-pkg --out extra.jsonl
 *
 * Labels are ground truth only: GHSA advisories of type "malware" are 1, the
 * reviewed benign list is 0. Vulnerability advisories are not malware and are
 * never used.
 *
 * Once npm takes a malicious package down the registry serves a "security
 * holding package" whose package.json has no scripts, so such a row would
 * teach the model that an empty manifest is malware. Those packages are
 * skipped (counted as `heldByNpm`); only advisories whose manifest is still
 * available contribute rows. The manifest used for a malware row is the
 * version the advisory names when present, else the latest real version.
 *
 * Feature keys: ml-model/feature-keys.json (behavioral) — produced by
 * ts/src/lib/behavioralFeatures.ts, which the scanner uses too.
 */

const fs = require('fs');
const path = require('path');

const featureManifest = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'feature-keys.json'), 'utf8')
);
const trainingDefaults = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'training-defaults.json'), 'utf8')
);
const KNOWN_GOOD = trainingDefaults.knownGoodPackages;
const BEHAVIORAL_FEATURE_KEYS = featureManifest.behavioral;

function loadBridge() {
  const libDir = path.join(__dirname, '..', 'ts', 'dist', 'lib');
  const bf = path.join(libDir, 'behavioralFeatures.js');
  const ph = path.join(libDir, 'publishHistory.js');
  if (!fs.existsSync(bf) || !fs.existsSync(ph)) {
    throw new Error(`Could not load ${bf}. From the repo root run: npm run build`);
  }
  return {
    behavioralFeaturesFromManifest: require(bf).behavioralFeaturesFromManifest,
    publishTimestamps: require(ph).publishTimestamps,
  };
}

function readPackageListFile(filePath) {
  if (!filePath || !fs.existsSync(filePath)) return [];
  return fs
    .readFileSync(filePath, 'utf8')
    .split(/\r?\n/)
    .map((line) => line.replace(/#.*$/, '').trim())
    .filter(Boolean);
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

const PLACEHOLDER_VERSION = /-(security|stage|placeholder)$/i;

function isHoldingPackage(data) {
  if (!data) return true;
  if (/security holding package/i.test(data.description || '')) return true;
  const maintainers = data.maintainers || [];
  if (maintainers.length === 1 && maintainers[0]?.name === 'npm') return true;
  return false;
}

/** Pick the manifest to describe: a real (non-placeholder) version, preferring `preferred`. */
function pickManifest(data, preferred) {
  const versions = data?.versions || {};
  if (preferred && versions[preferred])
    return { version: preferred, manifest: versions[preferred] };
  const latest = data?.['dist-tags']?.latest;
  if (latest && versions[latest] && !PLACEHOLDER_VERSION.test(latest)) {
    return { version: latest, manifest: versions[latest] };
  }
  const real = Object.keys(versions).filter((v) => !PLACEHOLDER_VERSION.test(v));
  const last = real[real.length - 1];
  return last ? { version: last, manifest: versions[last] } : null;
}

function normalize(features) {
  const out = {};
  for (const k of BEHAVIORAL_FEATURE_KEYS) {
    const v = features[k];
    out[k] = typeof v === 'number' && Number.isFinite(v) ? v : 0;
  }
  return out;
}

async function fetchGhsaMalware(options = {}) {
  const { limit = 100, token } = options;
  const headers = { Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' };
  if (token) headers.Authorization = `Bearer ${token}`;
  const seen = new Set();
  const packages = [];
  let url = 'https://api.github.com/advisories?ecosystem=npm&per_page=100&type=malware';
  const maxPages = Math.max(5, Math.ceil(limit / 100) + 2);
  for (let page = 0; page < maxPages && url && packages.length < limit; page++) {
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
          packages.push({
            name: pkg.name,
            ghsaId: adv.ghsa_id,
            publishedAt: adv.published_at || null,
            source: 'ghsa-malware',
            // "= 1.2.3" names the malicious version itself.
            version: (v.vulnerable_version_range || '').match(/^=\s*([\w.+-]+)$/)?.[1] ?? null,
          });
          if (packages.length >= limit) break;
        }
      }
    }
    const link = res.headers.get('link');
    const m = link && link.match(/<([^>]+)>;\s*rel="next"/);
    url = m ? m[1] : null;
  }
  return packages.slice(0, limit);
}

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

async function main() {
  const args = process.argv.slice(2);
  let goodPkgs = [...KNOWN_GOOD];
  let badPkgs = [];
  let outFile = 'train-behavioral.jsonl';
  let fromGhsa = false;
  let ghsaLimit = 100;
  let ghsaCache = null;
  let goodFile = null;
  let badFile = null;
  let overwrite = false;
  let concurrency = 8;
  const ghsaToken = process.env.GITHUB_TOKEN || null;

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--good' && args[i + 1])
      goodPkgs = args[++i]
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
    else if (a === '--bad' && args[i + 1])
      badPkgs = args[++i]
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
    else if (a === '--good-file' && args[i + 1]) goodFile = path.resolve(args[++i]);
    else if (a === '--bad-file' && args[i + 1]) badFile = path.resolve(args[++i]);
    else if (a === '--out' && args[i + 1]) outFile = args[++i];
    else if (a === '--from-ghsa') fromGhsa = true;
    else if (a === '--limit' && args[i + 1]) ghsaLimit = parseInt(args[++i], 10) || 100;
    else if (a === '--ghsa-cache' && args[i + 1]) ghsaCache = path.resolve(args[++i]);
    else if (a === '--overwrite') overwrite = true;
    else if (a === '--concurrency' && args[i + 1])
      concurrency = Math.max(1, parseInt(args[++i], 10) || 8);
  }
  goodPkgs = [...new Set([...goodPkgs, ...readPackageListFile(goodFile)])];
  badPkgs = [...new Set([...badPkgs, ...readPackageListFile(badFile)])];

  const bridge = loadBridge();
  const outPath = path.resolve(outFile);
  const rows = [];
  const seenNames = new Set();
  const seenVectors = new Set();
  const skipped = { noRegistry: 0, heldByNpm: 0, noManifest: 0, duplicate: 0 };

  function addRow(row) {
    if (seenNames.has(row.name)) {
      skipped.duplicate++;
      return;
    }
    seenNames.add(row.name);
    const key = JSON.stringify({ f: row.features, l: row.label });
    if (seenVectors.has(key)) {
      skipped.duplicate++;
      return;
    }
    seenVectors.add(key);
    rows.push(row);
  }

  if (!overwrite && fs.existsSync(outPath)) {
    for (const line of fs.readFileSync(outPath, 'utf8').trim().split('\n')) {
      try {
        const row = JSON.parse(line);
        if (row && typeof row.label === 'number' && row.features) {
          addRow({ name: row.name ?? JSON.stringify(row.features), ...row });
        }
      } catch {
        /* skip */
      }
    }
    if (rows.length)
      console.log(
        `Loaded ${rows.length} existing rows from ${outFile} (pass --overwrite to start fresh)`
      );
  }

  async function exportBatch(entries, label, defaultSource) {
    const built = await mapPool(entries, concurrency, async (entry) => {
      const name = typeof entry === 'string' ? entry : entry.name;
      const data = await fetchNpmMetadata(name);
      if (!data || !data.versions) {
        skipped.noRegistry++;
        return null;
      }
      if (label === 1 && isHoldingPackage(data)) {
        skipped.heldByNpm++;
        return null;
      }
      const picked = pickManifest(data, typeof entry === 'string' ? null : entry.version);
      if (!picked) {
        skipped.noManifest++;
        return null;
      }
      const stamps = bridge.publishTimestamps(data.time);
      const features = normalize(
        bridge.behavioralFeaturesFromManifest(picked.manifest, `${name}/package.json`)
      );
      return {
        features,
        label,
        name,
        version: picked.version,
        time: stamps.length ? stamps[0].toISOString() : (data.time?.created ?? null),
        reference: typeof entry === 'string' ? null : entry.publishedAt,
        source: typeof entry === 'string' ? defaultSource : entry.source || defaultSource,
        advisory: typeof entry === 'string' ? undefined : entry.ghsaId,
        exportedAt: new Date().toISOString(),
      };
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
    let ghsaPkgs;
    if (ghsaCache && fs.existsSync(ghsaCache)) {
      ghsaPkgs = JSON.parse(fs.readFileSync(ghsaCache, 'utf8')).slice(0, ghsaLimit);
      console.log(`Using cached advisory list ${ghsaCache}`);
    } else {
      ghsaPkgs = await fetchGhsaMalware({ limit: ghsaLimit, token: ghsaToken });
      if (ghsaCache) fs.writeFileSync(ghsaCache, JSON.stringify(ghsaPkgs, null, 1));
    }
    for (const p of ghsaPkgs) malwareNames.add(p.name);
    console.log(`Found ${ghsaPkgs.length} unique npm packages with malware advisories`);
    const added = await exportBatch(ghsaPkgs, 1, 'ghsa-malware');
    console.log(
      `  label 1: ${added} rows (${skipped.heldByNpm} skipped: manifest replaced by npm's security holding package)`
    );
  }

  const cleanGood = goodPkgs.filter((n) => !malwareNames.has(n));
  const goodAdded = await exportBatch(cleanGood, 0, goodFile ? 'benign-list' : 'known-good');
  console.log(`  label 0: ${goodAdded} rows`);

  if (badPkgs.length) {
    const badAdded = await exportBatch(badPkgs, 1, 'manual-malicious');
    console.log(`  label 1 (manual): ${badAdded} rows`);
  }

  fs.writeFileSync(outPath, rows.map((r) => JSON.stringify(r)).join('\n') + '\n');
  const pos = rows.filter((r) => r.label === 1).length;
  console.log(
    `Wrote ${rows.length} rows to ${outFile} (${pos} malicious / ${rows.length - pos} benign; skipped ${skipped.noRegistry} no registry, ${skipped.heldByNpm} held by npm, ${skipped.noManifest} no manifest, ${skipped.duplicate} duplicates)`
  );
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
