/**
 * Community Analysis Unit Tests
 */

const {
  runCommunityAnalysis,
  fetchNpmDownloads,
  fetchGitHubStars,
  fetchDependentsCount,
} = require('../../lib/communityAnalysis');
const axios = require('axios');

jest.mock('axios');

describe('Community Analysis', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('runCommunityAnalysis', () => {
    test('should return null when ENABLED is false', async () => {
      const result = await runCommunityAnalysis('lodash', '4.17.21', { ENABLED: false });
      expect(result).toBeNull();
      expect(axios.get).not.toHaveBeenCalled();
    });

    test('should return null for non-existent package when ENABLED', async () => {
      axios.get.mockResolvedValueOnce({ data: null });
      const result = await runCommunityAnalysis('non-existent-pkg-xyz-12345', '1.0.0', {
        ENABLED: true,
      });
      expect(result).toBeNull();
    });
  });

  describe('fetchNpmDownloads', () => {
    test('should return 0 when API fails', async () => {
      axios.get.mockRejectedValueOnce(new Error('Network error'));
      const result = await fetchNpmDownloads('lodash');
      expect(result).toBe(0);
    });

    test('should return download count when API succeeds', async () => {
      axios.get.mockResolvedValueOnce({ data: { downloads: 12345 } });
      const result = await fetchNpmDownloads('lodash');
      expect(result).toBe(12345);
    });
  });

  describe('fetchGitHubStars', () => {
    test('should return null for non-GitHub URL', async () => {
      const result = await fetchGitHubStars('https://example.com/owner/repo');
      expect(result).toBeNull();
      expect(axios.get).not.toHaveBeenCalled();
    });
  });

  describe('fetchDependentsCount', () => {
    test('should return null when USE_DEPENDENTS is false', async () => {
      const result = await fetchDependentsCount('lodash', { USE_DEPENDENTS: false });
      expect(result).toBeNull();
    });

    test('should return null when USE_DEPENDENTS is true', async () => {
      const result = await fetchDependentsCount('lodash', { USE_DEPENDENTS: true });
      expect(result).toBeNull();
    });
  });
});
