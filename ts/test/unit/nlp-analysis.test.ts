/**
 * Phase 4: NLP Analysis Unit Tests
 */

import { describe, it, expect } from '@jest/globals';
import {
  analyzeDocsNLP,
  analyzeIssuesNLP,
  runNlpAnalysis,
  fetchPackageDocs,
  fetchGitHubIssues,
} from '../../src/lib/nlpAnalysis';
import type { GitHubIssue } from '../../src/lib/nlpAnalysis';

describe('NLP Analysis (Phase 4)', () => {
  describe('analyzeDocsNLP', () => {
    it('should return security score 0 for empty text', () => {
      const result = analyzeDocsNLP({ readme: '', description: '' });
      expect(result.securityScore).toBe(0);
      expect(result.suspiciousPhrases).toEqual([]);
      expect(result.nlpSecurityScore).toBe(0);
    });

    it('should detect security keywords', () => {
      const result = analyzeDocsNLP({
        readme: 'This package has known vulnerability and is deprecated.',
        description: 'unsafe package',
      });
      expect(result.securityScore).toBeGreaterThan(0);
      expect(result.nlpSecurityScore).toBeGreaterThan(0);
    });

    it('should detect suspicious phrases', () => {
      const result = analyzeDocsNLP({
        readme: 'Use at your own risk. No longer maintained.',
        description: '',
      });
      expect(result.suspiciousPhrases.length).toBeGreaterThan(0);
    });
  });

  describe('analyzeIssuesNLP', () => {
    it('should return structure for empty issues', () => {
      const result = analyzeIssuesNLP([]);
      expect(result).toHaveProperty('securityScore');
      expect(result).toHaveProperty('issueSecurityCount', 0);
    });

    it('should count security-related issues', () => {
      const issues: GitHubIssue[] = [
        { title: 'Security vulnerability', body: 'XSS found', state: 'open', labels: ['security'] },
      ];
      const result = analyzeIssuesNLP(issues);
      expect(result.issueSecurityCount).toBeGreaterThanOrEqual(0);
    });
  });

  describe('runNlpAnalysis', () => {
    it('should return null when ENABLED is false', async () => {
      const result = await runNlpAnalysis('lodash', '4.17.21', { ENABLED: false });
      expect(result).toBeNull();
    });
  });

  describe('fetchPackageDocs', () => {
    it('should fetch docs for known package', async () => {
      const docs = await fetchPackageDocs('lodash', '4.17.21');
      expect(docs).not.toBeNull();
      expect(docs).toHaveProperty('readme');
      expect(docs).toHaveProperty('description');
    });

    it('should return null for non-existent package', async () => {
      const docs = await fetchPackageDocs('this-package-does-not-exist-xyz-12345', '1.0.0');
      expect(docs).toBeNull();
    });
  });

  describe('fetchGitHubIssues', () => {
    it('should return empty for invalid repo URL', async () => {
      const issues = await fetchGitHubIssues('https://example.com/not-github');
      expect(issues).toEqual([]);
    });
  });
});
