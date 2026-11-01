/**
 * Cache Analytics Tests
 */

import { describe, it, expect, beforeEach } from '@jest/globals';
import { CacheAnalytics, getCacheAnalytics } from '../../src/lib/cache/cacheAnalytics';
import type { MultiLayerCacheStats } from '../../src/types/cache-types';

describe('Cache Analytics', () => {
  let analytics: CacheAnalytics;

  beforeEach(() => {
    analytics = new CacheAnalytics();
  });

  it('should create analytics instance', () => {
    expect(analytics).toBeDefined();
  });

  it('should record stats', () => {
    const mockStats: MultiLayerCacheStats = {
      layers: {
        L1: {
          layer: 'L1',
          size: 10,
          maxSize: 100,
          hits: 50,
          misses: 10,
          evictions: 2,
          hitRate: 0.83,
          missRate: 0.17,
          utilization: 0.1
        },
        L2: {
          layer: 'L2',
          size: 5,
          maxSize: 50,
          hits: 20,
          misses: 5,
          evictions: 1,
          hitRate: 0.8,
          missRate: 0.2,
          utilization: 0.1
        },
        L3: {
          layer: 'L3',
          size: 0,
          maxSize: 0,
          hits: 0,
          misses: 0,
          evictions: 0,
          hitRate: 0,
          missRate: 0,
          utilization: 0
        }
      },
      totalHits: 70,
      totalMisses: 15,
      overallHitRate: 0.82,
      warming: false
    };

    analytics.recordStats(mockStats);
    
    const summary = analytics.getSummary(mockStats);
    expect(summary).toBeDefined();
    expect(summary.overall.hitRate).toBe(0.82);
  });

  it('should get summary', () => {
    const mockStats: MultiLayerCacheStats = {
      layers: {
        L1: {
          layer: 'L1',
          size: 10,
          maxSize: 100,
          hits: 50,
          misses: 10,
          evictions: 0,
          hitRate: 0.83,
          missRate: 0.17,
          utilization: 0.1
        },
        L2: {
          layer: 'L2',
          size: 5,
          maxSize: 50,
          hits: 20,
          misses: 5,
          evictions: 0,
          hitRate: 0.8,
          missRate: 0.2,
          utilization: 0.1
        },
        L3: {
          layer: 'L3',
          size: 0,
          maxSize: 0,
          hits: 0,
          misses: 0,
          evictions: 0,
          hitRate: 0,
          missRate: 0,
          utilization: 0
        }
      },
      totalHits: 70,
      totalMisses: 15,
      overallHitRate: 0.82,
      warming: false
    };

    const summary = analytics.getSummary(mockStats);
    
    expect(summary.overall).toBeDefined();
    expect(summary.layers).toBeDefined();
    expect(summary.layers['L1']).toBeDefined();
    expect(summary.layers['L2']).toBeDefined();
    expect(summary.layers['L3']).toBeDefined();
  });

  it('should get global analytics instance', () => {
    const globalAnalytics = getCacheAnalytics();
    expect(globalAnalytics).toBeDefined();
    expect(globalAnalytics).toBeInstanceOf(CacheAnalytics);
  });

  it('should generate report', () => {
    const mockStats: MultiLayerCacheStats = {
      layers: {
        L1: {
          layer: 'L1',
          size: 10,
          maxSize: 100,
          hits: 50,
          misses: 10,
          evictions: 0,
          hitRate: 0.83,
          missRate: 0.17,
          utilization: 0.1
        },
        L2: {
          layer: 'L2',
          size: 5,
          maxSize: 50,
          hits: 20,
          misses: 5,
          evictions: 0,
          hitRate: 0.8,
          missRate: 0.2,
          utilization: 0.1
        },
        L3: {
          layer: 'L3',
          size: 0,
          maxSize: 0,
          hits: 0,
          misses: 0,
          evictions: 0,
          hitRate: 0,
          missRate: 0,
          utilization: 0
        }
      },
      totalHits: 70,
      totalMisses: 15,
      overallHitRate: 0.82,
      warming: false
    };

    const report = analytics.generateReport(mockStats);
    
    expect(report).toBeDefined();
    expect(typeof report).toBe('string');
    expect(report.length).toBeGreaterThan(0);
  });
});

