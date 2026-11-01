/**
 * Multi-Layer Cache Tests
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { MultiLayerCache } from '../../src/lib/cache/multiLayerCache';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

describe('Multi-Layer Cache', () => {
  let cache: MultiLayerCache<string>;
  let testCacheDir: string;

  beforeEach(() => {
    // Create temporary cache directory
    testCacheDir = path.join(os.tmpdir(), `nullvoid-test-cache-${Date.now()}`);
    cache = new MultiLayerCache<string>();
  });

  afterEach(async () => {
    // Cleanup
    await cache.clear();
    if (fs.existsSync(testCacheDir)) {
      fs.rmSync(testCacheDir, { recursive: true, force: true });
    }
  });

  it('should create cache instance', () => {
    expect(cache).toBeDefined();
  });

  it('should set and get value from L1 cache', async () => {
    await cache.set('test-key', 'test-value');
    const result = await cache.get('test-key');
    
    expect(result.success).toBe(true);
    expect(result.value).toBe('test-value');
    expect(result.layer).toBe('L1');
  });

  it('should return null for non-existent key', async () => {
    const result = await cache.get('non-existent');
    expect(result.success).toBe(false);
  });

  it('should delete value', async () => {
    await cache.set('test-key', 'test-value');
    const deleted = await cache.delete('test-key');
    
    expect(deleted).toBe(true);
    
    const result = await cache.get('test-key');
    expect(result.success).toBe(false);
  });

  it('should clear all cache', async () => {
    await cache.set('key1', 'value1');
    await cache.set('key2', 'value2');
    
    await cache.clear();
    
    const result1 = await cache.get('key1');
    const result2 = await cache.get('key2');
    
    expect(result1.success).toBe(false);
    expect(result2.success).toBe(false);
  });

  it('should get cache statistics', () => {
    const stats = cache.getStats();
    
    expect(stats).toBeDefined();
    expect(stats.layers).toBeDefined();
    expect(stats.layers.L1).toBeDefined();
    expect(stats.layers.L2).toBeDefined();
    expect(stats.layers.L3).toBeDefined();
    expect(typeof stats.overallHitRate).toBe('number');
    expect(typeof stats.totalHits).toBe('number');
    expect(typeof stats.totalMisses).toBe('number');
  });
});

