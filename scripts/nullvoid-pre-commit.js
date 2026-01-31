#!/usr/bin/env node
/**
 * Pre-commit helper: run NullVoid and exit 1 if any threats are found.
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

// If scan failed to run (e.g. build error), exit with that code
if (result.status !== 0 && result.status !== null) {
  try { fs.unlinkSync(tempFile); } catch { /* ignore */ }
  process.exit(result.status);
}

let threatCount = 0;
try {
  if (fs.existsSync(tempFile)) {
    const data = JSON.parse(fs.readFileSync(tempFile, 'utf8'));
    const threats = data.threats;
    threatCount = Array.isArray(threats) ? threats.length : 0;
  }
} catch (e) {
  // No result or invalid JSON: allow commit (scan may have had no output)
} finally {
  try { fs.unlinkSync(tempFile); } catch { /* ignore */ }
}

if (threatCount > 0) {
  console.error(`\nNullVoid: ${threatCount} threat(s) found. Commit blocked. Fix or run nullvoid . for details.\n`);
  process.exit(1);
}

process.exit(0);
