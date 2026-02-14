/**
 * Phase 4: Anomaly Detection Unit Tests (JS)
 */

const { computeCrossPackageAnomaly, computeBehavioralAnomaly } = require('../../lib/anomalyDetection');

describe('Anomaly Detection (Phase 4)', () => {
  describe('computeCrossPackageAnomaly', () => {
    test('should return 0 for empty similar packages', () => {
      const result = computeCrossPackageAnomaly({ scriptCount: 5, dependencyCount: 10 }, []);
      expect(result).toBe(0);
    });

    test('should return higher score for deviant package', () => {
      const similar = [
        { scriptCount: 2, scriptTotalLength: 100, dependencyCount: 5, entropyScore: 0.3 },
        { scriptCount: 3, scriptTotalLength: 150, dependencyCount: 6, entropyScore: 0.4 }
      ];
      const normal = computeCrossPackageAnomaly({ scriptCount: 2, dependencyCount: 5 }, similar);
      const deviant = computeCrossPackageAnomaly({ scriptCount: 20, dependencyCount: 100 }, similar);
      expect(deviant).toBeGreaterThan(normal);
    });
  });

  describe('computeBehavioralAnomaly', () => {
    test('should return 0 for minimal features', () => {
      const result = computeBehavioralAnomaly({});
      expect(result).toBe(0);
    });

    test('should increase score for long postinstall', () => {
      const result = computeBehavioralAnomaly({
        hasPostinstall: true,
        postinstallLength: 600
      });
      expect(result).toBeGreaterThan(0);
    });

    test('should cap at 1', () => {
      const result = computeBehavioralAnomaly({
        hasPostinstall: true,
        postinstallLength: 1000,
        scriptCount: 10,
        entropyScore: 0.9
      });
      expect(result).toBeLessThanOrEqual(1);
    });
  });
});
