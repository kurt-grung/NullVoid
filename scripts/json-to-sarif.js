#!/usr/bin/env node
/**
 * Convert NullVoid security-report.json to SARIF 2.1 for GitHub Code Scanning upload.
 * Usage: node scripts/json-to-sarif.js [input.json] [output.sarif]
 * Defaults: security-report.json -> nullvoid-results.sarif
 * Requires `npm run build` so ts/dist is available.
 */

const fs = require('fs');
const path = require('path');

function main() {
  const workspaceRoot = process.cwd();
  const inputPath = process.argv[2] || path.join(workspaceRoot, 'security-report.json');
  const outputPath = process.argv[3] || path.join(workspaceRoot, 'nullvoid-results.sarif');

  let generateSarifOutput;
  try {
    ({ generateSarifOutput } = require(path.join(__dirname, '..', 'ts', 'dist', 'lib', 'sarif.js')));
  } catch (e) {
    console.error('Failed to load ts/dist/lib/sarif.js — run npm run build first.');
    console.error((e && e.message) || String(e));
    process.exit(1);
  }

  let report;
  try {
    report = JSON.parse(fs.readFileSync(inputPath, 'utf8'));
  } catch (e) {
    console.error('Failed to read or parse input:', (e && e.message) || String(e));
    process.exit(1);
  }

  let toolVersion = '0.0.0';
  try {
    toolVersion = require(path.join(workspaceRoot, 'package.json')).version || toolVersion;
  } catch {
    /* ignore */
  }

  const sarif = generateSarifOutput(report.threats || [], {
    riskAssessment: report.riskAssessment,
    toolVersion,
    workspaceRoot,
  });

  fs.writeFileSync(outputPath, JSON.stringify(sarif, null, 2), 'utf8');
  console.log('SARIF written to:', outputPath);
}

main();
