#!/usr/bin/env node
/**
 * Convert NullVoid security-report.json to SARIF 2.1 for GitHub Code Scanning upload.
 * Usage: node scripts/json-to-sarif.js [input.json] [output.sarif]
 * Defaults: security-report.json -> nullvoid-results.sarif
 */

const fs = require('fs');
const path = require('path');

const LEVEL_MAPPING = {
  CRITICAL: 'error',
  HIGH: 'error',
  MEDIUM: 'warning',
  LOW: 'note',
  INFO: 'note',
};

function threatToLocation(threat, workspaceRoot) {
  const raw = threat.filePath ?? threat.package ?? 'package.json';
  let uri = String(raw).replace(/^\s*[📁📦]\s*/, '').replace(/\x1b\[[0-9;]*m/g, '');
  if (path.isAbsolute(uri) && workspaceRoot) {
    try {
      uri = path.relative(workspaceRoot, uri);
    } catch {
      uri = path.basename(uri);
    }
  }
  if (!uri) uri = 'package.json';
  const loc = {
    physicalLocation: {
      artifactLocation: { uri },
    },
  };
  const line = threat.lineNumber;
  if (line != null && line >= 1) {
    loc.physicalLocation.region = {
      startLine: line,
      startColumn: 1,
    };
  }
  return loc;
}

function main() {
  const inputPath = process.argv[2] || path.join(process.cwd(), 'security-report.json');
  const outputPath = process.argv[3] || path.join(process.cwd(), 'nullvoid-results.sarif');
  const workspaceRoot = process.cwd();

  let report;
  try {
    report = JSON.parse(fs.readFileSync(inputPath, 'utf8'));
  } catch (e) {
    console.error('Failed to read or parse input:', e.message);
    process.exit(1);
  }

  const threats = report.threats || [];
  const ruleIds = [...new Set(threats.map((t) => t.type || 'UNKNOWN_THREAT'))];
  let pkgVersion = '0.0.0';
  try {
    pkgVersion = require(path.join(workspaceRoot, 'package.json')).version || pkgVersion;
  } catch {
    /* ignore */
  }

  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'NullVoid',
            version: pkgVersion,
            informationUri: 'https://github.com/kurt-grung/NullVoid',
            fullName: 'NullVoid Security Scanner',
            rules: ruleIds.map((id) => ({
              id,
              shortDescription: { text: id },
              defaultConfiguration: { level: 'error' },
            })),
          },
        },
        invocations: [
          {
            executionSuccessful: true,
            exitCode: threats.length > 0 ? 1 : 0,
            exitCodeDescription: threats.length > 0 ? 'Threats detected' : 'No threats detected',
          },
        ],
        results: threats.map((t) => ({
          ruleId: t.type || 'UNKNOWN_THREAT',
          level: LEVEL_MAPPING[t.severity] || 'note',
          message: { text: t.details ? `${t.message} — ${t.details}` : t.message },
          locations: [threatToLocation(t, workspaceRoot)],
        })),
      },
    ],
  };

  fs.writeFileSync(outputPath, JSON.stringify(sarif, null, 2), 'utf8');
  console.log('SARIF written to:', outputPath);
}

main();
