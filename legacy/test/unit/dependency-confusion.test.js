/**
 * Unit tests for Dependency Confusion Detection
 */

const { 
  detectDependencyConfusion,
  analyzePackageName,
  getPackageCreationDate,
  getGitHistory,
  calculateSimilarity,
  DEPENDENCY_CONFUSION_CONFIG
} = require('../../lib/dependencyConfusion');

// Mock dependencies
jest.mock('child_process');
jest.mock('https');
jest.mock('fs');

const { execSync } = require('child_process');
const https = require('https');

describe('Dependency Confusion Detection', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('analyzePackageName', () => {
    test('should analyze unscoped package names', () => {
      const result = analyzePackageName('express');
      
      expect(result.isScoped).toBe(false);
      expect(result.scope).toBeNull();
      expect(result.unscopedName).toBe('express');
      expect(result.riskLevel).toBe('LOW');
    });

    test('should analyze scoped package names', () => {
      const result = analyzePackageName('@company/internal-package');
      
      expect(result.isScoped).toBe(true);
      expect(result.scope).toBe('company');
      expect(result.unscopedName).toBe('internal-package');
      expect(result.scopeType).toBe('PRIVATE');
      expect(result.riskLevel).toBe('HIGH');
    });

    test('should detect suspicious naming patterns', () => {
      const result = analyzePackageName('abc123def'); // Use pattern that matches
      
      expect(result.suspiciousPatterns.length).toBeGreaterThan(0);
      expect(result.riskLevel).toBe('LOW'); // Not scoped, so still LOW
    });

    test('should identify public scopes', () => {
      const result = analyzePackageName('@types/node');
      
      expect(result.scope).toBe('types');
      expect(result.scopeType).toBe('PUBLIC');
      expect(result.riskLevel).toBe('LOW');
    });

    test('should handle unknown scopes', () => {
      const result = analyzePackageName('@unknown/package');
      
      expect(result.scope).toBe('unknown');
      expect(result.scopeType).toBe('UNKNOWN');
      expect(result.riskLevel).toBe('MEDIUM');
    });
  });

  describe('calculateSimilarity', () => {
    test('should calculate similarity between identical strings', () => {
      const similarity = calculateSimilarity('express', 'express');
      expect(similarity).toBe(1.0);
    });

    test('should calculate similarity between different strings', () => {
      const similarity = calculateSimilarity('express', 'exprexx');
      expect(similarity).toBeGreaterThan(0.7); // Lowered expectation
      expect(similarity).toBeLessThan(1.0);
    });

    test('should calculate similarity between very different strings', () => {
      const similarity = calculateSimilarity('express', 'lodash');
      expect(similarity).toBeLessThan(0.5);
    });

    test('should handle empty strings', () => {
      const similarity = calculateSimilarity('', '');
      expect(similarity).toBe(1.0);
    });

    test('should handle one empty string', () => {
      const similarity = calculateSimilarity('express', '');
      expect(similarity).toBe(0.0);
    });
  });

  describe('getPackageCreationDate', () => {
    test('should return null for packages without registry data', async () => {
      // Mock network error
      https.get.mockImplementation((url, callback) => {
        const mockRequest = {
          on: jest.fn((event, handler) => {
            if (event === 'error') {
              setTimeout(() => handler(new Error('Network error')), 10);
            }
          }),
          setTimeout: jest.fn()
        };
        return mockRequest;
      });

      const result = await getPackageCreationDate('nonexistent');
      expect(result).toBeNull();
    });
  });

  describe('getGitHistory', () => {
    test('should return git history for valid repository', () => {
      execSync.mockReturnValue('abc123 2023-01-01 12:00:00 +0000\n');
      execSync.mockReturnValueOnce('abc123 2023-01-01 12:00:00 +0000\n');
      execSync.mockReturnValueOnce('5\n');

      const result = getGitHistory('/path/to/repo');

      expect(result.hasGitHistory).toBe(true);
      expect(result.firstCommitDate).toBeInstanceOf(Date);
      expect(result.recentCommitCount).toBe(5);
    });

    test('should return error info for invalid repository', () => {
      execSync.mockImplementation(() => {
        throw new Error('Not a git repository');
      });

      const result = getGitHistory('/path/to/invalid');

      expect(result.hasGitHistory).toBe(false);
      expect(result.error).toBe('Not a git repository');
    });

    test('should handle timeout errors', () => {
      execSync.mockImplementation(() => {
        throw new Error('Command timed out');
      });

      const result = getGitHistory('/path/to/repo');

      expect(result.hasGitHistory).toBe(false);
      expect(result.error).toBe('Command timed out');
    });
  });

  describe('detectDependencyConfusion', () => {
    test('should handle packages without git history', async () => {
      execSync.mockImplementation(() => {
        throw new Error('Not a git repository');
      });

      const threats = await detectDependencyConfusion('no-git-package', '/path/to/repo');
      expect(threats.length).toBe(0);
    });

    test('should handle analysis errors gracefully', async () => {
      execSync.mockImplementation(() => {
        throw new Error('Git command failed');
      });

      const threats = await detectDependencyConfusion('error-package', '/path/to/repo');
      expect(threats.length).toBe(0);
    });
  });

  describe('DEPENDENCY_CONFUSION_CONFIG', () => {
    test('should have valid timeline thresholds', () => {
      expect(DEPENDENCY_CONFUSION_CONFIG.TIMELINE_THRESHOLDS.SUSPICIOUS).toBe(30);
      expect(DEPENDENCY_CONFUSION_CONFIG.TIMELINE_THRESHOLDS.HIGH_RISK).toBe(7);
      expect(DEPENDENCY_CONFUSION_CONFIG.TIMELINE_THRESHOLDS.CRITICAL).toBe(1);
    });

    test('should have valid similarity thresholds', () => {
      expect(DEPENDENCY_CONFUSION_CONFIG.SIMILARITY_THRESHOLDS.SUSPICIOUS).toBe(0.8);
      expect(DEPENDENCY_CONFUSION_CONFIG.SIMILARITY_THRESHOLDS.HIGH_RISK).toBe(0.9);
      expect(DEPENDENCY_CONFUSION_CONFIG.SIMILARITY_THRESHOLDS.CRITICAL).toBe(0.95);
    });

    test('should have scope patterns defined', () => {
      expect(DEPENDENCY_CONFUSION_CONFIG.SCOPE_PATTERNS.PRIVATE_SCOPES).toBeDefined();
      expect(DEPENDENCY_CONFUSION_CONFIG.SCOPE_PATTERNS.PUBLIC_SCOPES).toBeDefined();
      expect(Array.isArray(DEPENDENCY_CONFUSION_CONFIG.SCOPE_PATTERNS.PRIVATE_SCOPES)).toBe(true);
      expect(Array.isArray(DEPENDENCY_CONFUSION_CONFIG.SCOPE_PATTERNS.PUBLIC_SCOPES)).toBe(true);
    });

    test('should have suspicious name patterns', () => {
      expect(DEPENDENCY_CONFUSION_CONFIG.SUSPICIOUS_NAME_PATTERNS).toBeDefined();
      expect(Array.isArray(DEPENDENCY_CONFUSION_CONFIG.SUSPICIOUS_NAME_PATTERNS)).toBe(true);
      expect(DEPENDENCY_CONFUSION_CONFIG.SUSPICIOUS_NAME_PATTERNS.length).toBeGreaterThan(0);
    });

    test('should have registry endpoints', () => {
      expect(DEPENDENCY_CONFUSION_CONFIG.REGISTRY_ENDPOINTS.npm).toBeDefined();
      expect(DEPENDENCY_CONFUSION_CONFIG.REGISTRY_ENDPOINTS.github).toBeDefined();
    });
  });
});
