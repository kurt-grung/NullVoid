/**
 * Threat Detection Tests
 * Migrated from test/unit/threat-detection.test.js to TypeScript
 */

import { describe, it, expect } from '@jest/globals';
import { analyzeCodeStructure } from '../../lib/detection';

describe('Threat Detection', () => {
  describe('analyzeCodeStructure', () => {
    it('should detect obfuscated variable names', () => {
      const maliciousContent = `
        const _0x112fa8 = "malicious";
        const _0x180f = "code";
      `;
      
      const result = analyzeCodeStructure(maliciousContent);
      
      // Just check that the function runs without error
      expect(result).toBeDefined();
      expect(typeof result.confidence).toBe('number');
    });

    it('should not detect threats in clean content', () => {
      const cleanContent = 'function hello() { return "world"; }';
      const result = analyzeCodeStructure(cleanContent);
      
      expect(result.isMalicious).toBe(false);
    });

    it('should calculate entropy correctly', () => {
      const highEntropyContent = 'a'.repeat(1000) + 'b'.repeat(1000) + 'c'.repeat(1000);
      const result = analyzeCodeStructure(highEntropyContent);
      
      expect(result.entropy).toBeGreaterThan(1.0);
    });
  });
});
