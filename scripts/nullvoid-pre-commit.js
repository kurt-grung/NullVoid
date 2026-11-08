#!/usr/bin/env node
/**
 * Pre-commit helper: run NullVoid and block the commit when it exits 1 (threats)
 * or 2 (scan error).
 * Uses --depth 1 for speed and --no-ioc to skip NVD/GHSA/etc. (avoids CVE keyword false positives).
 * Run from repo/project root. Used by .husky/pre-commit when NULLVOID_PRE_COMMIT=1.
 */

const path = require('path');
const fs = require('fs');
const { spawnSync } = require('child_process');
const os = require('os');

const cwd = process.cwd();
const tempFile = path.join(os.tmpdir(), `nullvoid-precommit-${Date.now()}.json`);

// Prefer local NullVoid build (NullVoid repo), else npx
const repoRoot = path.resolve(__dirname, '..');
const localBin = path.join(repoRoot, 'ts', 'dist', 'bin', 'nullvoid.js');
const useLocal = fs.existsSync(localBin);
const cmd = useLocal ? 'node' : 'npx';
// --no-ioc: skip IoC lookups (NVD/GHSA/npm/Snyk) to avoid keyword false positives (e.g. "husky" → HUSKY RTU CVEs)
const cmdArgs = useLocal
  ? [localBin, '.', '--output', tempFile, '--depth', '1', '--no-ioc']
  : ['nullvoid', '.', '--output', tempFile, '--depth', '1', '--no-ioc'];

const result = spawnSync(cmd, cmdArgs, {
  cwd,
  stdio: 'inherit',
  shell: true,
});

// NullVoid's exit-code contract: 0 clean, 1 threats at/above --fail-on
// (default HIGH), 2 scan error. The JSON report is kept for the message only.
const status = result.status ?? 2;

let threatCount = 0;
try {
  if (fs.existsSync(tempFile)) {
    const data = JSON.parse(fs.readFileSync(tempFile, 'utf8'));
    const threats = data.threats || [];
    threatCount = Array.isArray(threats) ? threats.length : 0;
  }
} catch {
  /* report unreadable; rely on the exit code */
}
try { fs.unlinkSync(tempFile); } catch { /* ignore */ }

if (status === 2) {
  console.error('NullVoid: scan did not complete. Commit blocked.');
  process.exit(2);
}
if (status === 1) {
  console.error(`NullVoid: ${threatCount || 'one or more'} threat(s) found. Commit blocked.`);
  process.exit(1);
}
process.exit(0);
