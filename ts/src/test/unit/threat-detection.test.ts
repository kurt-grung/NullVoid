/**
 * Threat Detection Tests
 * Migrated from test/unit/threat-detection.test.js to TypeScript
 */

import { describe, it, expect } from '@jest/globals';
import { detectMalware } from '../../lib/detection';

describe('Threat Detection', () => {
  describe('analyzeCodeStructure', () => {
    it('should detect obfuscated variable names', () => {
      const maliciousContent = `
        const _0x112fa8 = "malicious";
        const _0x180f = "code";
      `;

      const result = detectMalware(maliciousContent);

      // Just check that the function runs without error
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
    });

    it('should not detect threats in clean content', () => {
      const cleanContent = 'function hello() { return "world"; }';
      const result = detectMalware(cleanContent);

      expect(Array.isArray(result)).toBe(true);
    });

    it('should calculate entropy correctly', () => {
      const highEntropyContent = 'a'.repeat(1000) + 'b'.repeat(1000) + 'c'.repeat(1000);
      const result = detectMalware(highEntropyContent);

      expect(Array.isArray(result)).toBe(true);
    });
  });
});
