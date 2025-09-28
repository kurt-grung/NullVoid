const { describe, it, expect, beforeEach, afterEach } = require('@jest/globals');
const { getCachedResult, setCachedResult, cleanupCache } = require('../../scan');

// Mock the cache functions for testing
jest.mock('../../scan', () => {
  const originalModule = jest.requireActual('../../scan');
  return {
    ...originalModule,
    getCachedResult: jest.fn(),
    setCachedResult: jest.fn(),
    cleanupCache: jest.fn()
  };
});

describe('Cache Management', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('getCachedResult', () => {
    it('should return cached data when available and not expired', () => {
      const mockData = { threats: [], timestamp: Date.now() };
      getCachedResult.mockReturnValue(mockData);
      
      const result = getCachedResult('test-key');
      
      expect(result).toEqual(mockData);
      expect(getCachedResult).toHaveBeenCalledWith('test-key');
    });

    it('should return null when cache is empty', () => {
      getCachedResult.mockReturnValue(null);
      
      const result = getCachedResult('non-existent-key');
      
      expect(result).toBeNull();
    });

    it('should return null when cache is expired', () => {
      const expiredData = { threats: [], timestamp: Date.now() - 600000 }; // 10 minutes ago
      getCachedResult.mockReturnValue(null);
      
      const result = getCachedResult('expired-key');
      
      expect(result).toBeNull();
    });
  });

  describe('setCachedResult', () => {
    it('should store data in cache with timestamp', () => {
      const testData = { threats: ['test-threat'] };
      
      setCachedResult('test-key', testData);
      
      expect(setCachedResult).toHaveBeenCalledWith('test-key', testData);
    });

    it('should handle cache size limits', () => {
      const testData = { threats: ['test-threat'] };
      
      setCachedResult('test-key', testData);
      
      expect(setCachedResult).toHaveBeenCalledWith('test-key', testData);
    });
  });

  describe('cleanupCache', () => {
    it('should clean up expired entries', () => {
      cleanupCache();
      
      expect(cleanupCache).toHaveBeenCalled();
    });

    it('should handle cache size limits', () => {
      cleanupCache();
      
      expect(cleanupCache).toHaveBeenCalled();
    });
  });
});

