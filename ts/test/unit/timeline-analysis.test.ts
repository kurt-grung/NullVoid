/**
 * Timeline Analysis Unit Tests
 */

import { describe, it, expect } from '@jest/globals';
import {
  buildTimelineEvents,
  daysBetween,
  getTimelineRiskLevel,
  timelineAnomalyScore,
  analyzeTimeline,
} from '../../src/lib/timelineAnalysis';

describe('Timeline Analysis', () => {
  describe('daysBetween', () => {
    it('should compute days between two dates', () => {
      const a = new Date('2024-01-01');
      const b = new Date('2024-01-11');
      expect(daysBetween(a, b)).toBe(10);
    });

    it('should return absolute difference', () => {
      const a = new Date('2024-01-11');
      const b = new Date('2024-01-01');
      expect(daysBetween(a, b)).toBe(10);
    });
  });

  describe('getTimelineRiskLevel', () => {
    it('should return CRITICAL for very small days difference', () => {
      expect(getTimelineRiskLevel(0)).toBe('CRITICAL');
      expect(getTimelineRiskLevel(1)).toBe('CRITICAL');
    });

    it('should return HIGH for small days difference', () => {
      expect(getTimelineRiskLevel(2)).toBe('HIGH');
      expect(getTimelineRiskLevel(3)).toBe('HIGH');
    });

    it('should return MEDIUM for moderate days difference', () => {
      expect(getTimelineRiskLevel(5)).toBe('MEDIUM');
      expect(getTimelineRiskLevel(7)).toBe('MEDIUM');
    });

    it('should return LOW for large days difference', () => {
      expect(getTimelineRiskLevel(30)).toBe('LOW');
      expect(getTimelineRiskLevel(365)).toBe('LOW');
    });
  });

  describe('timelineAnomalyScore', () => {
    it('should return higher score for very recent registry', () => {
      const recent = timelineAnomalyScore({ daysDifference: 0.5, recentCommitCount: 0 });
      const old = timelineAnomalyScore({ daysDifference: 100, recentCommitCount: 0 });
      expect(recent).toBeGreaterThan(old);
    });

    it('should cap score at 1', () => {
      const score = timelineAnomalyScore({
        daysDifference: 0,
        recentCommitCount: 0,
        hasScopeConflict: true,
      });
      expect(score).toBeLessThanOrEqual(1);
    });
  });

  describe('buildTimelineEvents', () => {
    it('should sort events by date', () => {
      const events = buildTimelineEvents({
        registryCreated: '2024-01-15',
        firstCommitDate: '2024-01-01',
      });
      expect(events).toHaveLength(2);
      expect(events[0]!.type).toBe('first_commit');
      expect(events[1]!.type).toBe('registry_created');
    });
  });

  describe('analyzeTimeline', () => {
    it('should return full analysis with anomaly score', () => {
      const result = analyzeTimeline({
        registryCreated: new Date('2024-01-10'),
        firstCommitDate: new Date('2024-01-01'),
        recentCommitCount: 2,
      });
      expect(result.daysDifference).toBe(9);
      expect(result.riskLevel).toBeDefined();
      expect(result.anomalyScore).toBeGreaterThanOrEqual(0);
      expect(result.anomalyScore).toBeLessThanOrEqual(1);
    });

    it('should return LOW risk when no registry date', () => {
      const result = analyzeTimeline({
        firstCommitDate: new Date('2024-01-01'),
      });
      expect(result.riskLevel).toBe('LOW');
      expect(result.daysDifference).toBeNull();
    });
  });
});
