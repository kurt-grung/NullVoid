/**
 * Unit tests for Commit Pattern Analysis (Phase 2)
 */

const { execSync } = require('child_process');
jest.mock('child_process');

const {
  getRepoRoot,
  analyzeCommitPatterns,
  commitPatternAnomalyScore,
  analyzeCommitMessagePatterns,
  analyzeDiffPatterns
} = require('../../lib/commitPatternAnalysis');

describe('Commit Pattern Analysis (Phase 2)', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('getRepoRoot', () => {
    test('should return root when in git repo', () => {
      execSync.mockReturnValue('/some/repo\n');
      const root = getRepoRoot('/some/repo/subdir');
      expect(root).toBe('/some/repo');
    });

    test('should return null when not in git repo', () => {
      execSync.mockImplementation(() => {
        throw new Error('not a git repo');
      });
      const root = getRepoRoot('/tmp/not-repo');
      expect(root).toBeNull();
    });
  });

  describe('analyzeCommitPatterns', () => {
    test('should return structure with defaults when no git', () => {
      execSync.mockImplementation((cmd) => {
        if (cmd.includes('rev-parse')) throw new Error('not a git repo');
        return '';
      });
      const result = analyzeCommitPatterns('/tmp/not-repo');
      expect(result).toHaveProperty('authorCount', 0);
      expect(result).toHaveProperty('totalCommitCount', 0);
      expect(result).toHaveProperty('hasGitHistory', false);
      expect(result).toHaveProperty('repoRoot', null);
    });

    test('should populate when git commands return data', () => {
      let callIndex = 0;
      execSync.mockImplementation((cmd) => {
        if (cmd.includes('rev-parse')) return '/repo\n';
        if (cmd.includes('rev-list --count HEAD') && !cmd.includes('since=')) return '42';
        if (cmd.includes('log -1 --format=%ci --reverse')) return '2023-01-01 12:00:00 +0000';
        if (cmd.includes('log -1 --format=%ci HEAD') && !cmd.includes('--reverse')) return '2024-06-01 12:00:00 +0000';
        if (cmd.includes('shortlog')) return '  30\tAlice\n  12\tBob';
        if (cmd.includes('branch -a')) return '  main\n  feature';
        if (cmd.includes('90 days ago')) return '10';
        if (cmd.includes('30 days ago')) return '3';
        return '';
      });
      const result = analyzeCommitPatterns('/repo');
      expect(result.repoRoot).toBe('/repo');
      expect(result.totalCommitCount).toBe(42);
      expect(result.authorCount).toBe(2);
      expect(result.hasMultipleAuthors).toBe(true);
      expect(result.dominantAuthorShare).toBeCloseTo(30 / 42);
      expect(result.firstCommitDate).toBeInstanceOf(Date);
      expect(result.lastCommitDate).toBeInstanceOf(Date);
      expect(result.recentCommitCount90d).toBe(10);
      expect(result.recentCommitCount30d).toBe(3);
    });
  });

  describe('commitPatternAnomalyScore', () => {
    test('should return 0.5 when no git history', () => {
      const score = commitPatternAnomalyScore({ hasGitHistory: false });
      expect(score).toBe(0.5);
    });

    test('should increase for single author and low activity', () => {
      const low = commitPatternAnomalyScore({
        hasGitHistory: true,
        hasMultipleAuthors: true,
        totalCommitCount: 100,
        dateRangeDays: 365,
        recentCommitCount90d: 20,
        dominantAuthorShare: 0.3
      });
      const high = commitPatternAnomalyScore({
        hasGitHistory: true,
        hasMultipleAuthors: false,
        totalCommitCount: 5,
        dateRangeDays: 10,
        recentCommitCount90d: 0,
        dominantAuthorShare: 1
      });
      expect(high).toBeGreaterThan(low);
      expect(high).toBeLessThanOrEqual(1);
    });
  });

  describe('analyzeCommitMessagePatterns', () => {
    test('should return structure with messages and anomalyScore', () => {
      execSync.mockImplementation((cmd) => {
        if (cmd.includes('log') && cmd.includes('%s')) return 'fix\nupdate\nreal feature here';
        return '';
      });
      const result = analyzeCommitMessagePatterns('/repo');
      expect(result).toHaveProperty('messages');
      expect(result).toHaveProperty('suspiciousCount');
      expect(result).toHaveProperty('anomalyScore');
      expect(Array.isArray(result.messages)).toBe(true);
    });
  });

  describe('analyzeDiffPatterns', () => {
    test('should return structure with diff stats and anomalyScore', () => {
      execSync.mockImplementation((cmd) => {
        if (cmd.includes('numstat')) return '10\t5\tfile.js\n';
        return '';
      });
      const result = analyzeDiffPatterns('/repo');
      expect(result).toHaveProperty('recentCommitsWithLargeDiffs');
      expect(result).toHaveProperty('avgAdditions');
      expect(result).toHaveProperty('avgDeletions');
      expect(result).toHaveProperty('anomalyScore');
    });
  });
});
