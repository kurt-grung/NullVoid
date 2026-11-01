#!/usr/bin/env node
/**
 * Merge human feedback labels into dependency-model training data.
 *
 * Usage:
 *   node export-feedback.js --feedback feedback.jsonl --out train.jsonl
 */

const fs = require('fs');
const path = require('path');

async function fetchNpmMetadata(packageName) {
  try {
    const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(packageName)}`);
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

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

function buildFeatures(pkgName, data) {
  const created = data?.time?.created ? new Date(data.time.created) : null;
  const now = new Date();
  const daysSinceCreation = created ? Math.abs(now - created) / (1000 * 60 * 60 * 24) : 365;
  const daysDifference = Math.min(365, daysSinceCreation);
  const scopePrivate = pkgName.startsWith('@') ? 1 : 0;
  const suspiciousPatterns = /^[a-z0-9]{32,}$/i.test(pkgName) ? 1 : 0;
  return {
    daysDifference,
    recentCommitCount: 0,
    scopePrivate,
    suspiciousPatternsCount: suspiciousPatterns,
    timelineAnomaly: timelineAnomalyScore(daysSinceCreation, 0, scopePrivate === 1),
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
}

async function main() {
  const args = process.argv.slice(2);
  let feedbackFile = 'feedback.jsonl';
  let outFile = 'train.jsonl';
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--feedback' && args[i + 1]) feedbackFile = args[++i];
    else if (args[i] === '--out' && args[i + 1]) outFile = args[++i];
  }

  const feedbackPath = path.resolve(feedbackFile);
  const outPath = path.resolve(outFile);
  if (!fs.existsSync(feedbackPath)) {
    throw new Error(`Feedback file not found: ${feedbackPath}`);
  }

  const dedupe = new Set();
  const rows = [];
  if (fs.existsSync(outPath)) {
    for (const line of fs.readFileSync(outPath, 'utf8').split('\n')) {
      if (!line.trim()) continue;
      try {
        const row = JSON.parse(line);
        const key = JSON.stringify({ f: row.features, l: row.label });
        dedupe.add(key);
        rows.push(row);
      } catch {
        // skip invalid
      }
    }
  }

  const feedbackRows = fs
    .readFileSync(feedbackPath, 'utf8')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => JSON.parse(line));

  let added = 0;
  for (const fb of feedbackRows) {
    const packageName = fb.packageName;
    const label = Number(fb.label);
    if (!packageName || (label !== 0 && label !== 1)) continue;
    const data = await fetchNpmMetadata(packageName);
    const features = buildFeatures(packageName, data);
    const row = {
      features,
      label,
      exportedAt: new Date().toISOString(),
      source: 'feedback',
      packageName,
      version: fb.version || 'latest',
      scanId: fb.scanId || null,
    };
    const key = JSON.stringify({ f: row.features, l: row.label });
    if (dedupe.has(key)) continue;
    dedupe.add(key);
    rows.push(row);
    added++;
  }

  fs.writeFileSync(outPath, rows.map((r) => JSON.stringify(r)).join('\n') + '\n', 'utf8');
  console.log(`Merged feedback rows into ${outPath}. Added ${added} rows.`);
}

main().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});
