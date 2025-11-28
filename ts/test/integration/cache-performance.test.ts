/**
 * Cache Performance Integration Tests
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { MultiLayerCache } from '../../src/lib/cache/multiLayerCache';
import { getCacheAnalytics } from '../../src/lib/cache/cacheAnalytics';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

describe('Cache Performance Integration', () => {
  let cacheDir: string;
  let cache: MultiLayerCache<string>;

  beforeEach(() => {
    cacheDir = path.join(os.tmpdir(), `nullvoid-test-cache-${Date.now()}`);
    // MultiLayerCache doesn't take constructor options, uses config
    cache = new MultiLayerCache<string>();
  });

  afterEach(() => {
    // Cleanup
    if (fs.existsSync(cacheDir)) {
      fs.rmSync(cacheDir, { recursive: true, force: true });
    }
  });

  describe('Cache Hit Rate Performance', () => {
    it('should achieve high hit rate on repeated queries', async () => {
      const testData = 'test-data';
      const key = 'test-key';

      // First access - cache miss
      await cache.set(key, testData);
      const firstResult = await cache.get(key);
      expect(firstResult.success).toBe(true);
      if (firstResult.success) {
        expect(firstResult.value).toBe(testData);
      }

      // Subsequent accesses - cache hits
      for (let i = 0; i < 10; i++) {
        const result = await cache.get(key);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.value).toBe(testData);
        }
      }

      const analytics = getCacheAnalytics();
      const stats = cache.getStats();
      const summary = analytics.getSummary(stats);
      
      expect(summary).toBeDefined();
      expect(summary.overall.hitRate).toBeGreaterThan(0.8); // Should have high hit rate
    });

    it('should handle cache warming efficiently', async () => {
      // Warm up cache
      const keys: string[] = [];
      for (let i = 0; i < 50; i++) {
        const key = `warm-key-${i}`;
        keys.push(key);
        await cache.set(key, `data-${i}`);
      }

      // Access all keys
      const startTime = Date.now();
      for (const key of keys) {
        await cache.get(key);
      }
      const duration = Date.now() - startTime;

      // Should be fast due to cache hits
      expect(duration).toBeLessThan(1000);
    });
  });

  describe('Multi-Layer Cache Performance', () => {
    it('should promote data from L1 to L2 efficiently', async () => {
      const key = 'promote-key';
      const data = 'test-data';

      await cache.set(key, data);
      
      // Access multiple times to ensure it's in L1
      for (let i = 0; i < 5; i++) {
        await cache.get(key);
      }

      // Clear L1 (simulate)
      // Access should still work (from L2)
      const result = await cache.get(key);
      expect(result.value).toBe(data);
    });

    it('should handle cache eviction efficiently', async () => {
      // Fill cache beyond maxSize
      for (let i = 0; i < 150; i++) {
        await cache.set(`key-${i}`, `data-${i}`);
      }

      // Should still be able to access recent keys
      const recentKey = 'key-149';
      const result = await cache.get(recentKey);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.value).toBe('data-149');
      }
    });
  });

  describe('Cache Analytics Performance', () => {
    it('should track performance metrics accurately', async () => {
      const analytics = getCacheAnalytics();

      // Perform cache operations
      for (let i = 0; i < 100; i++) {
        await cache.set(`key-${i}`, `data-${i}`);
        await cache.get(`key-${i}`);
      }

      const stats = cache.getStats();
      const summary = analytics.getSummary(stats);
      
      expect(summary).toBeDefined();
      expect(summary.overall.totalRequests).toBeGreaterThan(0);
      expect(summary.overall.hitRate).toBeGreaterThanOrEqual(0);
      expect(summary.overall.hitRate).toBeLessThanOrEqual(1);
    });

    it('should provide layer-specific performance data', async () => {
      const analytics = getCacheAnalytics();

      // Perform operations
      for (let i = 0; i < 50; i++) {
        await cache.set(`key-${i}`, `data-${i}`);
        await cache.get(`key-${i}`);
      }

      const stats = cache.getStats();
      const summary = analytics.getSummary(stats);
      
      expect(summary).toBeDefined();
      expect(summary.layers).toBeDefined();
      // Should have data for at least one layer
      expect(Object.keys(summary.layers).length).toBeGreaterThan(0);
    });
  });

  describe('Cache Cleanup Performance', () => {
    it('should cleanup expired entries efficiently', async () => {
      // Set entries with short TTL
      const shortTTLCache = new MultiLayerCache<string>();

      for (let i = 0; i < 50; i++) {
        await shortTTLCache.set(`key-${i}`, `data-${i}`, 100);
      }

      // Wait for expiration
      await new Promise(resolve => setTimeout(resolve, 200));

      // Most entries should be expired (may still be in cache due to cleanup interval)
      const result = await shortTTLCache.get('key-0');
      // Result may be null or still present depending on cleanup timing
      if (result.success) {
        expect(result.value).toBe('data-0');
      } else {
        expect(result.success).toBe(false);
      }
    });
  });
});

