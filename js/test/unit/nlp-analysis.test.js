/**
 * NLP Analysis Unit Tests
 */

const {
  analyzeDocsNLP,
  analyzeIssuesNLP,
  runNlpAnalysis,
  fetchPackageDocs,
  DEFAULT_NLP_CONFIG
} = require('../../lib/nlpAnalysis');

describe('NLP Analysis', () => {
  describe('analyzeDocsNLP', () => {
    test('should return security score 0 for empty text', () => {
      const result = analyzeDocsNLP({ readme: '', description: '' });
      expect(result.securityScore).toBe(0);
      expect(result.suspiciousPhrases).toEqual([]);
    });

    test('should detect security keywords', () => {
      const result = analyzeDocsNLP({
        readme: 'This package has known vulnerability.',
        description: 'deprecated'
      });
      expect(result.securityScore).toBeGreaterThan(0);
    });
  });

  describe('analyzeIssuesNLP', () => {
    test('should return structure for empty issues', () => {
      const result = analyzeIssuesNLP([]);
      expect(result).toHaveProperty('securityScore');
      expect(result).toHaveProperty('issueSecurityCount', 0);
    });
  });

  describe('runNlpAnalysis', () => {
    test('should return null when ENABLED is false', async () => {
      const result = await runNlpAnalysis('lodash', '4.17.21', { ENABLED: false });
      expect(result).toBeNull();
    });
  });

  describe('fetchPackageDocs', () => {
    test('should fetch docs for known package', async () => {
      const docs = await fetchPackageDocs('lodash', '4.17.21');
      expect(docs).not.toBeNull();
      expect(docs).toHaveProperty('readme');
      expect(docs).toHaveProperty('description');
    });
  });

  describe('DEFAULT_NLP_CONFIG', () => {
    test('should have expected shape', () => {
      expect(DEFAULT_NLP_CONFIG).toHaveProperty('ENABLED');
      expect(DEFAULT_NLP_CONFIG).toHaveProperty('MAX_ISSUES');
      expect(DEFAULT_NLP_CONFIG).toHaveProperty('SKIP_IF_NO_REPO');
    });
  });
});
