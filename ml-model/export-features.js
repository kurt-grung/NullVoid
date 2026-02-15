#!/usr/bin/env node
/**
 * Export feature vectors for ML training.
 * Usage:
 *   node export-features.js --good lodash,react,express --out good.jsonl
 *   node export-features.js --bad package1,package2 --out bad.jsonl
 *   node export-features.js --good lodash,react --bad malicious-pkg --out train.jsonl
 *
 * Known-good defaults: lodash, react, express, axios, chalk
 * Known-bad: pass via --bad or use --from-ghsa (fetches recent advisories)
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

function buildMinimalFeatures(pkgName, data, label) {
  const created = data?.time?.created
    ? new Date(data.time.created)
    : null;
  const now = new Date();
  const daysSinceCreation = created
    ? Math.abs(now - created) / (1000 * 60 * 60 * 24)
    : 365;
  const daysDifference = Math.min(365, daysSinceCreation);
  const isScoped = pkgName.startsWith('@');
  const scopePrivate = isScoped ? 1 : 0;
  const suspiciousPatterns = /^[a-z0-9]{32,}$/i.test(pkgName) ? 1 : 0;
  const timelineAnomaly =
    daysSinceCreation <= 1 ? 0.5
    : daysSinceCreation <= 7 ? 0.35
    : daysSinceCreation <= 30 ? 0.2
    : 0;

  return {
    features: {
      daysDifference,
      recentCommitCount: 0,
      scopePrivate,
      suspiciousPatternsCount: suspiciousPatterns,
      timelineAnomaly,
      registryIsNpm: 1,
      nlpSecurityScore: 0,
      nlpSuspiciousCount: 0,
      crossPackageAnomaly: 0,
      behavioralAnomaly: 0,
      reviewSecurityScore: 0.5,
      popularityScore: 0.5,
      trustScore: 0.5,
    },
    label,
  };
}

async function main() {
  const args = process.argv.slice(2);
  let goodPkgs = KNOWN_GOOD;
  let badPkgs = [];
  let outFile = 'train.jsonl';

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--good' && args[i + 1]) {
      goodPkgs = args[++i].split(',').map((s) => s.trim()).filter(Boolean);
    } else if (args[i] === '--bad' && args[i + 1]) {
      badPkgs = args[++i].split(',').map((s) => s.trim()).filter(Boolean);
    } else if (args[i] === '--out' && args[i + 1]) {
      outFile = args[++i];
    }
  }

  const lines = [];

  for (const name of goodPkgs) {
    const data = await fetchNpmMetadata(name);
    const row = buildMinimalFeatures(name, data, 0);
    lines.push(JSON.stringify(row));
  }

  for (const name of badPkgs) {
    const data = await fetchNpmMetadata(name);
    const row = buildMinimalFeatures(name, data, 1);
    lines.push(JSON.stringify(row));
  }

  const fs = await import('fs');
  fs.writeFileSync(outFile, lines.join('\n') + '\n');
  console.log(`Wrote ${lines.length} rows to ${outFile}`);
}

main().catch(console.error);
