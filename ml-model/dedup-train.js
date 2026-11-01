#!/usr/bin/env node
/**
 * Deduplicate train.jsonl by feature vector (keeps first occurrence per unique features+label).
 * Use before training when combining data from multiple sources (export-features, scan).
 *
 * Usage:
 *   node dedup-train.js [input.jsonl] [output.jsonl]
 *   node dedup-train.js                    # defaults: train.jsonl -> train.jsonl (in-place)
 *   node dedup-train.js train.jsonl out.jsonl
 */

const fs = require('fs');
const path = require('path');

const input = process.argv[2] || 'train.jsonl';
const output = process.argv[3] || input;

const inputPath = path.resolve(input);
const outputPath = path.resolve(output);

if (!fs.existsSync(inputPath)) {
  console.error(`File not found: ${inputPath}`);
  process.exit(1);
}

const content = fs.readFileSync(inputPath, 'utf8').trim();
const seen = new Set();
const rows = [];

for (const line of content.split('\n')) {
  if (!line.trim()) continue;
  try {
    const row = JSON.parse(line);
    if (!row || typeof row.label !== 'number' || !row.features) continue;
    const key = JSON.stringify({ f: row.features, l: row.label });
    if (seen.has(key)) continue;
    seen.add(key);
    rows.push(row);
  } catch {
    /* skip invalid lines */
  }
}

const lines = rows.map((r) => JSON.stringify(r));
fs.writeFileSync(outputPath, lines.join('\n') + '\n');
console.log(`Deduplicated: ${content.split('\n').filter(Boolean).length} -> ${rows.length} rows`);
if (outputPath !== inputPath) {
  console.log(`Wrote ${outputPath}`);
}
