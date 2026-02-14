/**
 * Phase 4: Anomaly Detection Unit Tests
 */

import { describe, it, expect } from '@jest/globals';
import {
  computeCrossPackageAnomaly,
  computeBehavioralAnomaly,
} from '../../src/lib/anomalyDetection';
import type { SimilarPackageStats } from '../../src/lib/anomalyDetection';

describe('Anomaly Detection (Phase 4)', () => {
  describe('computeCrossPackageAnomaly', () => {
    it('should use typical baseline when no similar packages and return deviation score', () => {
      // Empty array triggers typical npm baseline; package deviating from typical gets non-zero score
      const typical = computeCrossPackageAnomaly(
        { scriptCount: 4, scriptTotalLength: 600, dependencyCount: 6 },
        []
      );
      const deviant = computeCrossPackageAnomaly(
        { scriptCount: 20, scriptTotalLength: 5000, dependencyCount: 100 },
        []
      );
      expect(deviant).toBeGreaterThan(typical);
      expect(typical).toBeLessThan(0.5); // close to baseline
      expect(deviant).toBeGreaterThan(0.5); // deviates from baseline
    });

    it('should use typical baseline for null/undefined similar packages', () => {
      const result = computeCrossPackageAnomaly(
        { scriptCount: 5, dependencyCount: 10 },
        (null as unknown) as SimilarPackageStats[]
      );
      expect(result).toBeGreaterThanOrEqual(0);
      expect(result).toBeLessThanOrEqual(1);
    });

    it('should return higher score for deviant package', () => {
      const similar: SimilarPackageStats[] = [
        { scriptCount: 2, scriptTotalLength: 100, dependencyCount: 5, entropyScore: 0.3 },
        { scriptCount: 3, scriptTotalLength: 150, dependencyCount: 6, entropyScore: 0.4 },
        { scriptCount: 2, scriptTotalLength: 120, dependencyCount: 4, entropyScore: 0.35 },
      ];
      const normal = computeCrossPackageAnomaly(
        { scriptCount: 2, dependencyCount: 5, entropyScore: 0.35 },
        similar
      );
      const deviant = computeCrossPackageAnomaly(
        { scriptCount: 20, dependencyCount: 100, entropyScore: 0.9 },
        similar
      );
      expect(deviant).toBeGreaterThan(normal);
    });
  });

  describe('computeBehavioralAnomaly', () => {
    it('should return 0 for minimal features', () => {
      const result = computeBehavioralAnomaly({});
      expect(result).toBe(0);
    });

    it('should increase score for long postinstall', () => {
      const result = computeBehavioralAnomaly({
        hasPostinstall: true,
        postinstallLength: 600,
      });
      expect(result).toBeGreaterThan(0);
    });

    it('should increase score for many scripts', () => {
      const result = computeBehavioralAnomaly({ scriptCount: 10 });
      expect(result).toBeGreaterThan(0);
    });

    it('should increase score for high entropy', () => {
      const result = computeBehavioralAnomaly({ entropyScore: 0.8 });
      expect(result).toBeGreaterThan(0);
    });

    it('should cap at 1', () => {
      const result = computeBehavioralAnomaly({
        hasPostinstall: true,
        postinstallLength: 1000,
        scriptCount: 10,
        rareDependencyCount: 5,
        entropyScore: 0.9,
      });
      expect(result).toBeLessThanOrEqual(1);
    });
  });
});
