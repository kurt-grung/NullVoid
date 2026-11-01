/**
 * Unit tests for composite risk scoring (C/I/A model)
 */

import { describe, it, expect } from '@jest/globals';
import { computeCompositeRisk } from '../../src/lib/riskScoring';
import type { Threat } from '../../src/types/core';

function makeThreat(overrides: Partial<Threat> = {}): Threat {
  return {
    type: 'MALICIOUS_CODE',
    message: 'Test threat',
    severity: 'HIGH',
    details: '',
    filePath: 'test.js',
    filename: 'test.js',
    confidence: 0.9,
    ...overrides,
  };
}

describe('Risk Scoring', () => {
  describe('computeCompositeRisk', () => {
    it('should return 0 overall for empty threats', () => {
      const result = computeCompositeRisk([]);
      expect(result.overall).toBe(0);
      expect(result.byCategory.confidentiality).toBe(0);
      expect(result.byCategory.integrity).toBe(0);
      expect(result.byCategory.availability).toBe(0);
      expect(result.bySeverity.CRITICAL).toBe(0);
      expect(result.bySeverity.HIGH).toBe(0);
    });

    it('should map threats to C/I/A categories', () => {
      const threats: Threat[] = [
        makeThreat({ type: 'DATA_EXFILTRATION', severity: 'HIGH' }),
        makeThreat({ type: 'CRYPTO_MINING', severity: 'MEDIUM' }),
      ];
      const result = computeCompositeRisk(threats);
      expect(result.byCategory.confidentiality).toBeGreaterThan(0);
      expect(result.byCategory.availability).toBeGreaterThan(0);
    });

    it('should increase overall for higher severity', () => {
      const low = computeCompositeRisk([
        makeThreat({ severity: 'LOW', confidence: 0.5 }),
      ]);
      const high = computeCompositeRisk([
        makeThreat({ severity: 'CRITICAL', confidence: 0.9 }),
      ]);
      expect(high.overall).toBeGreaterThan(0);
      expect(high.overall).toBeGreaterThanOrEqual(low.overall);
    });

    it('should cap overall at 1', () => {
      const threats: Threat[] = Array.from({ length: 20 }, () =>
        makeThreat({ severity: 'CRITICAL', confidence: 1 })
      );
      const result = computeCompositeRisk(threats);
      expect(result.overall).toBeLessThanOrEqual(1);
    });

    it('should accumulate bySeverity for valid severities', () => {
      const threats: Threat[] = [
        makeThreat({ severity: 'CRITICAL', confidence: 0.8 }),
        makeThreat({ severity: 'CRITICAL', confidence: 0.5 }),
        makeThreat({ severity: 'HIGH', confidence: 0.9 }),
      ];
      const result = computeCompositeRisk(threats);
      expect(result.bySeverity.CRITICAL).toBeGreaterThan(0);
      expect(result.bySeverity.HIGH).toBeGreaterThan(0);
    });

    it('should ignore invalid severity values', () => {
      const threats: Threat[] = [
        makeThreat({ severity: 'CRITICAL' as any }),
        makeThreat({ severity: 'INVALID' as any }),
      ];
      const result = computeCompositeRisk(threats);
      expect(result.bySeverity.CRITICAL).toBeGreaterThan(0);
      expect(result.bySeverity).not.toHaveProperty('INVALID');
    });

    it('should default unknown threat types to integrity', () => {
      const threats: Threat[] = [
        makeThreat({ type: 'UNKNOWN_TYPE' as any, severity: 'HIGH' }),
      ];
      const result = computeCompositeRisk(threats);
      expect(result.byCategory.integrity).toBeGreaterThan(0);
    });

    it('should round overall to 2 decimal places', () => {
      const result = computeCompositeRisk([
        makeThreat({ severity: 'MEDIUM', confidence: 0.5 }),
      ]);
      const str = result.overall.toString();
      const decimalPart = str.split('.')[1] || '';
      expect(decimalPart.length).toBeLessThanOrEqual(2);
    });
  });
});
