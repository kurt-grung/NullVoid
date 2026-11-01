/**
 * Commit Pattern Analysis Unit Tests
 */

import { describe, it, expect } from '@jest/globals';
import {
  getRepoRoot,
  analyzeCommitPatterns,
  commitPatternAnomalyScore,
} from '../../src/lib/commitPatternAnalysis';

describe('Commit Pattern Analysis', () => {
  describe('getRepoRoot', () => {
    it('should return repo root when in git repo', () => {
      const root = getRepoRoot(process.cwd());
      expect(root).toBeTruthy();
      expect(typeof root).toBe('string');
    });

    it('should return null for non-git directory', () => {
      const root = getRepoRoot('/tmp');
      expect(root).toBeNull();
    });
  });

  describe('analyzeCommitPatterns', () => {
    it('should return structure with git history when in repo', () => {
      const result = analyzeCommitPatterns(process.cwd());
      expect(result).toHaveProperty('authorCount');
      expect(result).toHaveProperty('totalCommitCount');
      expect(result).toHaveProperty('hasGitHistory');
      expect(result).toHaveProperty('repoRoot');
      expect(result).toHaveProperty('dominantAuthorShare');
    });

    it('should return empty structure when not in repo', () => {
      const result = analyzeCommitPatterns('/tmp');
      expect(result.hasGitHistory).toBe(false);
      expect(result.repoRoot).toBeNull();
      expect(result.authorCount).toBe(0);
    });
  });

  describe('commitPatternAnomalyScore', () => {
    it('should return 0.5 when no git history', () => {
      const patterns = {
        hasGitHistory: false,
        authorCount: 0,
        totalCommitCount: 0,
        dateRangeDays: null,
        recentCommitCount90d: 0,
        dominantAuthorShare: 0,
        hasMultipleAuthors: false,
        firstCommitDate: null,
        lastCommitDate: null,
        branchCount: 0,
        recentCommitCount30d: 0,
        repoRoot: null,
      } as Parameters<typeof commitPatternAnomalyScore>[0];
      expect(commitPatternAnomalyScore(patterns)).toBe(0.5);
    });

    it('should return higher score for single author and low activity', () => {
      const suspicious = {
        hasGitHistory: true,
        authorCount: 1,
        totalCommitCount: 5,
        dateRangeDays: 10,
        recentCommitCount90d: 1,
        dominantAuthorShare: 1,
        hasMultipleAuthors: false,
        firstCommitDate: null,
        lastCommitDate: null,
        branchCount: 1,
        recentCommitCount30d: 0,
        repoRoot: '/tmp',
      } as Parameters<typeof commitPatternAnomalyScore>[0];
      const normal = {
        ...suspicious,
        authorCount: 5,
        totalCommitCount: 100,
        dateRangeDays: 365,
        recentCommitCount90d: 20,
        hasMultipleAuthors: true,
      } as Parameters<typeof commitPatternAnomalyScore>[0];
      expect(commitPatternAnomalyScore(suspicious)).toBeGreaterThan(
        commitPatternAnomalyScore(normal)
      );
    });

    it('should cap score at 1', () => {
      const patterns = {
        hasGitHistory: true,
        authorCount: 1,
        totalCommitCount: 1,
        dateRangeDays: 1,
        recentCommitCount90d: 0,
        dominantAuthorShare: 1,
        hasMultipleAuthors: false,
        firstCommitDate: null,
        lastCommitDate: null,
        branchCount: 1,
        recentCommitCount30d: 0,
        repoRoot: '/tmp',
      } as Parameters<typeof commitPatternAnomalyScore>[0];
      expect(commitPatternAnomalyScore(patterns)).toBeLessThanOrEqual(1);
    });
  });
});
