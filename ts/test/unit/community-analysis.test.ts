/**
 * Community Analysis Unit Tests
 */

import { describe, it, expect, beforeEach } from '@jest/globals';
import {
  runCommunityAnalysis,
  fetchNpmDownloads,
  fetchGitHubStars,
  fetchDependentsCount,
} from '../../src/lib/communityAnalysis';
import axios from 'axios';

jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe('Community Analysis', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('runCommunityAnalysis', () => {
    it('should return null when ENABLED is false', async () => {
      const result = await runCommunityAnalysis('lodash', '4.17.21', { ENABLED: false });
      expect(result).toBeNull();
      expect(mockedAxios.get).not.toHaveBeenCalled();
    });

    it('should return null for non-existent package when ENABLED', async () => {
      mockedAxios.get.mockResolvedValueOnce({ data: null });
      const result = await runCommunityAnalysis('non-existent-pkg-xyz-12345', '1.0.0', {
        ENABLED: true,
      });
      expect(result).toBeNull();
    });

    it('should return CommunityAnalysisResult when ENABLED and package exists', async () => {
      const registryData = {
        versions: {
          '4.17.21': {
            version: '4.17.21',
            description: 'Lodash utilities',
            repository: { url: 'git+https://github.com/lodash/lodash.git' },
          },
        },
        'dist-tags': { latest: '4.17.21' },
        time: {
          created: '2012-04-23T00:00:00.000Z',
          modified: '2024-01-15T00:00:00.000Z',
          '4.17.21': '2021-02-20T00:00:00.000Z',
        },
        readme: 'Lodash utilities',
      };
      mockedAxios.get.mockImplementation((url: string) => {
        if (url.includes('api.npmjs.org/downloads')) {
          return Promise.resolve({ data: { downloads: 5000000 } });
        }
        if (url.includes('api.github.com/repos')) {
          return Promise.resolve({ data: { stargazers_count: 50000 } });
        }
        if (url.includes('registry.npmjs.org')) {
          return Promise.resolve({ data: registryData });
        }
        return Promise.reject(new Error(`Unexpected URL: ${url}`));
      });

      const result = await runCommunityAnalysis('lodash', '4.17.21', {
        ENABLED: true,
        USE_DOWNLOADS: true,
        USE_GITHUB_STARS: true,
      });

      expect(result).not.toBeNull();
      expect(result).toHaveProperty('downloadCountWeekly');
      expect(result).toHaveProperty('githubStars');
      expect(result).toHaveProperty('dependentsCount');
      expect(result).toHaveProperty('maintenanceScore');
      expect(result).toHaveProperty('popularityScore');
      expect(result).toHaveProperty('reviewSecurityScore');
      expect(typeof result!.maintenanceScore).toBe('number');
      expect(typeof result!.popularityScore).toBe('number');
      expect(result!.maintenanceScore).toBeGreaterThanOrEqual(0);
      expect(result!.maintenanceScore).toBeLessThanOrEqual(1);
      expect(result!.popularityScore).toBeGreaterThanOrEqual(0);
      expect(result!.popularityScore).toBeLessThanOrEqual(1);
    });
  });

  describe('fetchNpmDownloads', () => {
    it('should return 0 when API fails', async () => {
      mockedAxios.get.mockRejectedValueOnce(new Error('Network error'));
      const result = await fetchNpmDownloads('lodash');
      expect(result).toBe(0);
    });

    it('should return download count when API succeeds', async () => {
      mockedAxios.get.mockResolvedValueOnce({ data: { downloads: 12345 } });
      const result = await fetchNpmDownloads('lodash');
      expect(result).toBe(12345);
    });
  });

  describe('fetchGitHubStars', () => {
    it('should return null for non-GitHub URL', async () => {
      const result = await fetchGitHubStars('https://example.com/owner/repo');
      expect(result).toBeNull();
      expect(mockedAxios.get).not.toHaveBeenCalled();
    });

    it('should return null when API fails', async () => {
      mockedAxios.get.mockRejectedValueOnce(new Error('Not found'));
      const result = await fetchGitHubStars('https://github.com/lodash/lodash');
      expect(result).toBeNull();
    });
  });

  describe('fetchDependentsCount', () => {
    it('should return null when USE_DEPENDENTS is false', async () => {
      const result = await fetchDependentsCount('lodash', { USE_DEPENDENTS: false });
      expect(result).toBeNull();
    });

    it('should return null when USE_DEPENDENTS is true (no API)', async () => {
      const result = await fetchDependentsCount('lodash', { USE_DEPENDENTS: true });
      expect(result).toBeNull();
    });
  });
});
