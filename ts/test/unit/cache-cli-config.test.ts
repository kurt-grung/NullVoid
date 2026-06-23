import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import {
  applyCacheCliOptions,
  CACHE_LAYER_CONFIG,
  IOC_CONFIG,
} from '../../src/lib/config';

describe('applyCacheCliOptions', () => {
  const originalL3Enabled = (CACHE_LAYER_CONFIG.L3 as { enabled: boolean }).enabled;
  const originalMultiLayer = IOC_CONFIG.USE_MULTI_LAYER_CACHE;

  beforeEach(() => {
    (CACHE_LAYER_CONFIG.L3 as Record<string, unknown>)['enabled'] = false;
    (IOC_CONFIG as Record<string, unknown>)['USE_MULTI_LAYER_CACHE'] = false;
  });

  afterEach(() => {
    (CACHE_LAYER_CONFIG.L3 as Record<string, unknown>)['enabled'] = originalL3Enabled;
    (IOC_CONFIG as Record<string, unknown>)['USE_MULTI_LAYER_CACHE'] = originalMultiLayer;
  });

  it('enables L3 and multi-layer IoC cache when enableRedis is true', () => {
    applyCacheCliOptions({ enableRedis: true });

    expect((CACHE_LAYER_CONFIG.L3 as { enabled: boolean }).enabled).toBe(true);
    expect(IOC_CONFIG.USE_MULTI_LAYER_CACHE).toBe(true);
  });

  it('does not change config when enableRedis is false', () => {
    applyCacheCliOptions({ enableRedis: false });

    expect((CACHE_LAYER_CONFIG.L3 as { enabled: boolean }).enabled).toBe(false);
    expect(IOC_CONFIG.USE_MULTI_LAYER_CACHE).toBe(false);
  });
});
