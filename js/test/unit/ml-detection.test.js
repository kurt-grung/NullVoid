/**
 * Unit tests for ML detection scaffold (Phase 2)
 */

const {
  buildFeatureVector,
  computeThreatScore,
  runMLDetection
} = require('../../lib/mlDetection');

describe('ML Detection (Phase 2)', () => {
  describe('buildFeatureVector', () => {
    test('should build feature vector from params', () => {
      const features = buildFeatureVector({
        daysDifference: 5,
        recentCommitCount: 2,
        scopeType: 'PRIVATE',
        suspiciousPatternsCount: 1,
        registryName: 'npm'
      });
      expect(features).toHaveProperty('daysDifference', 5);
      expect(features).toHaveProperty('recentCommitCount', 2);
      expect(features).toHaveProperty('scopePrivate', 1);
      expect(features).toHaveProperty('suspiciousPatternsCount', 1);
      expect(features).toHaveProperty('timelineAnomaly');
      expect(features).toHaveProperty('registryIsNpm', 1);
    });
  });

  describe('computeThreatScore', () => {
    test('should return 0 for empty/low features', () => {
      const score = computeThreatScore({
        daysDifference: 365,
        recentCommitCount: 100,
        scopePrivate: 0,
        suspiciousPatternsCount: 0,
        timelineAnomaly: 0,
        registryIsNpm: 1
      });
      expect(score).toBeGreaterThanOrEqual(0);
      expect(score).toBeLessThanOrEqual(1);
    });

    test('should increase score for private scope and timeline anomaly', () => {
      const low = computeThreatScore({
        daysDifference: 365,
        recentCommitCount: 50,
        scopePrivate: 0,
        suspiciousPatternsCount: 0,
        timelineAnomaly: 0,
        registryIsNpm: 1
      });
      const high = computeThreatScore({
        daysDifference: 1,
        recentCommitCount: 2,
        scopePrivate: 1,
        suspiciousPatternsCount: 2,
        timelineAnomaly: 0.8,
        registryIsNpm: 1
      });
      expect(high).toBeGreaterThan(low);
      expect(high).toBeLessThanOrEqual(1);
    });

    test('should accept custom weights', () => {
      const features = { timelineAnomaly: 1, scopePrivate: 1, suspiciousPatternsCount: 0, recentCommitCount: 0, daysDifference: 1, registryIsNpm: 1 };
      const defaultScore = computeThreatScore(features);
      const customScore = computeThreatScore(features, { timelineAnomaly: 0.9, scopePrivate: 0.1, suspiciousPatterns: 0, lowActivityRecent: 0 });
      expect(customScore).not.toBe(defaultScore);
      expect(customScore).toBeLessThanOrEqual(1);
    });
  });

  describe('runMLDetection', () => {
    test('should return enabled, anomalyScore, threatScore, aboveThreshold, features', () => {
      const result = runMLDetection({
        creationDate: new Date('2024-01-01'),
        firstCommitDate: new Date('2024-01-02'),
        recentCommitCount: 1,
        scopeType: 'PRIVATE',
        suspiciousPatternsCount: 1,
        registryName: 'npm'
      });
      expect(result).toHaveProperty('enabled');
      expect(result).toHaveProperty('anomalyScore');
      expect(result).toHaveProperty('threatScore');
      expect(result).toHaveProperty('aboveThreshold');
      expect(result).toHaveProperty('features');
      expect(result.anomalyScore).toBeGreaterThanOrEqual(0);
      expect(result.anomalyScore).toBeLessThanOrEqual(1);
      expect(result.threatScore).toBeGreaterThanOrEqual(0);
      expect(result.threatScore).toBeLessThanOrEqual(1);
    });
  });
});
