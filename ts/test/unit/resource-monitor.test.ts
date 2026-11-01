/**
 * Resource Monitor Tests
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { ResourceMonitor, getResourceMonitor } from '../../src/lib/parallel/resourceMonitor';

describe('Resource Monitor', () => {
  let monitor: ResourceMonitor;

  beforeEach(() => {
    monitor = new ResourceMonitor();
  });

  afterEach(() => {
    monitor.stopMonitoring();
  });

  it('should create monitor instance', () => {
    expect(monitor).toBeDefined();
  });

  it('should get system metrics', () => {
    const metrics = monitor.getMetrics();
    
    expect(metrics).toBeDefined();
    expect(typeof metrics.cpuUsage).toBe('number');
    expect(typeof metrics.memoryUsage).toBe('number');
    expect(typeof metrics.loadAverage).toBe('number');
    expect(typeof metrics.availableMemory).toBe('number');
    expect(typeof metrics.totalMemory).toBe('number');
    expect(typeof metrics.cpuCores).toBe('number');
    expect(metrics.cpuUsage).toBeGreaterThanOrEqual(0);
    expect(metrics.cpuUsage).toBeLessThanOrEqual(100);
    expect(metrics.memoryUsage).toBeGreaterThanOrEqual(0);
    expect(metrics.memoryUsage).toBeLessThanOrEqual(100);
  });

  it('should get resource recommendations', () => {
    const recommendations = monitor.getRecommendations(4, 10, 5);
    
    expect(recommendations).toBeDefined();
    expect(typeof recommendations.recommendedWorkers).toBe('number');
    expect(typeof recommendations.recommendedChunkSize).toBe('number');
    expect(typeof recommendations.scaleUp).toBe('boolean');
    expect(typeof recommendations.scaleDown).toBe('boolean');
    expect(typeof recommendations.reason).toBe('string');
    expect(recommendations.recommendedWorkers).toBeGreaterThan(0);
  });

  it('should start and stop monitoring', () => {
    monitor.startMonitoring(1000);
    expect(monitor).toBeDefined();
    
    monitor.stopMonitoring();
    // Should not throw error
    expect(monitor).toBeDefined();
  });

  it('should get current metrics', () => {
    // First call to initialize
    monitor.getMetrics();
    
    const currentMetrics = monitor.getCurrentMetrics();
    expect(currentMetrics).toBeDefined();
  });

  it('should get global monitor instance', () => {
    const globalMonitor = getResourceMonitor();
    expect(globalMonitor).toBeDefined();
    expect(globalMonitor).toBeInstanceOf(ResourceMonitor);
    // Clean up global instance if it was started
    globalMonitor.stopMonitoring();
  });
});

