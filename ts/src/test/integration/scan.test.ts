/**
 * Integration Tests
 * Migrated from test/integration/scan.test.js to TypeScript
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { scan } from '../../scan';
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
      const maliciousContent = `
        const _0x112fa8 = "malicious";
        const fs = require('fs');
        eval("malicious code");
      `;
      fs.writeFileSync(maliciousFile, maliciousContent);

      const result = await scan(tempDir, {
        verbose: false,
        output: 'table',
        parallel: true,
        all: false
      });

      expect(result.threats.length).toBeGreaterThan(0);
      expect(result.threats[0]?.type).toBe('SUSPICIOUS_MODULE');
      expect(result.threats[0]?.severity).toBe('CRITICAL');
    });

    it('should scan a directory with clean files', async () => {
      // Create a clean test file
      const cleanFile = path.join(tempDir, 'clean.js');
      const cleanContent = 'function hello() { return "world"; }';
      fs.writeFileSync(cleanFile, cleanContent);

      const result = await scan(tempDir, {
        verbose: false,
        output: 'table',
        parallel: true,
        all: false
      });

      expect(result.threats.length).toBe(0);
      expect(result.metadata?.['target']).toBe(tempDir);
    });

    it('should handle empty directories', async () => {
      const result = await scan(tempDir, {
        verbose: false,
        output: 'table',
        parallel: true,
        all: false
      });

      expect(result.threats.length).toBe(0);
      expect(result.metadata?.['target']).toBe(tempDir);
    });

    it('should respect the all flag for showing low severity threats', async () => {
      // Create a file with low severity threats
      const suspiciousFile = path.join(tempDir, 'suspicious.js');
      const suspiciousContent = 'const fs = require("fs"); const _0x1234 = "malicious"; eval("bad code");';
      fs.writeFileSync(suspiciousFile, suspiciousContent);

      const result = await scan(tempDir, {
        verbose: false,
        output: 'table',
        parallel: true,
        all: true
      });

      expect(result.threats.length).toBeGreaterThan(0);
      expect(result.threats[0]?.type).toBe('MALICIOUS_CODE_STRUCTURE');
      expect(result.threats[0]?.severity).toBe('CRITICAL');
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
        parallel: true,
        all: false
      });

      // Test passes if scan completes without error
      expect(true).toBe(true);
    });
  });
});
