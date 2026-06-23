import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';

const mockStore = new Map<string, unknown>();

jest.mock('../../src/lib/cache/redisCache', () => ({
  createRedisCache: jest.fn(() => ({
    get: jest.fn(async <T>(key: string): Promise<T | null> => {
      const value = mockStore.get(key);
      return value !== undefined ? (value as T) : null;
    }),
    set: jest.fn(async (key: string, value: unknown) => {
      mockStore.set(key, value);
      return true;
    }),
    delete: jest.fn(async (key: string) => {
      const existed = mockStore.has(key);
      mockStore.delete(key);
      return existed;
    }),
    clear: jest.fn(async () => {
      mockStore.clear();
    }),
    getStatus: jest.fn(() => ({
      enabled: true,
      available: true,
      connected: true,
      connectionAttempts: 0,
    })),
    close: jest.fn(async () => undefined),
  })),
}));

import { MultiLayerCache } from '../../src/lib/cache/multiLayerCache';
import { CACHE_LAYER_CONFIG } from '../../src/lib/config';

describe('MultiLayerCache L3 integration', () => {
  let cache: MultiLayerCache<string>;
  const originalL3Enabled = (CACHE_LAYER_CONFIG.L3 as { enabled: boolean }).enabled;

  beforeEach(() => {
    mockStore.clear();
    (CACHE_LAYER_CONFIG.L3 as Record<string, unknown>)['enabled'] = true;
    cache = new MultiLayerCache<string>();
  });

  afterEach(async () => {
    await cache.clear();
    await cache.close();
    (CACHE_LAYER_CONFIG.L3 as Record<string, unknown>)['enabled'] = originalL3Enabled;
  });

  it('reads from L3 when L1 and L2 miss', async () => {
    mockStore.set('remote-key', 'remote-value');

    const result = await cache.get('remote-key');

    expect(result.success).toBe(true);
    expect(result.value).toBe('remote-value');
    expect(result.layer).toBe('L3');
  });

  it('writes through to L3 on set', async () => {
    await cache.set('persist-key', 'persist-value');

    expect(mockStore.get('persist-key')).toBe('persist-value');
  });

  it('reports L3 stats after hits', async () => {
    mockStore.set('stats-key', 'stats-value');
    await cache.get('stats-key');

    const stats = cache.getStats();

    expect(stats.layers.L3.hits).toBe(1);
    expect(stats.layers.L3.hitRate).toBe(1);
    expect(cache.getL3Status()?.connected).toBe(true);
  });

  it('clears L3 entries', async () => {
    await cache.set('clear-key', 'clear-value');
    await cache.clear();

    expect(mockStore.size).toBe(0);
  });
});
