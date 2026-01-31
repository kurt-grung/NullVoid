/**
 * Cache Analytics Module
 * Tracks and reports cache performance metrics
 */

import type { MultiLayerCacheStats } from '../../types/cache-types';
import { logger } from '../logger';

/**
 * Cache analytics tracker
 */
export class CacheAnalytics {
  private statsHistory: MultiLayerCacheStats[] = [];
  private maxHistorySize = 100;
  private startTime: number;

  constructor() {
    this.startTime = Date.now();
  }

  /**
   * Record cache statistics
   */
  recordStats(stats: MultiLayerCacheStats): void {
    this.statsHistory.push({ ...stats });

    // Keep only recent history
    if (this.statsHistory.length > this.maxHistorySize) {
      this.statsHistory.shift();
    }
  }

  /**
   * Get current statistics summary
   */
  getSummary(stats: MultiLayerCacheStats): {
    overall: {
      hitRate: number;
      totalRequests: number;
      averageResponseTime: number;
    };
    layers: Record<
      string,
      {
        hitRate: number;
        utilization: number;
        size: number;
      }
    >;
    recommendations: string[];
  } {
    const recommendations: string[] = [];

    // Analyze L1 cache
    if (stats.layers.L1.hitRate < 0.5) {
      recommendations.push('L1 cache hit rate is low. Consider increasing cache size or TTL.');
    }

    // Analyze L2 cache
    if (stats.layers.L2.utilization > 0.9) {
      recommendations.push(
        'L2 cache is nearly full. Consider increasing max size or enabling cleanup.'
      );
    }

    // Overall recommendations
    if (stats.overallHitRate < 0.3) {
      recommendations.push(
        'Overall cache hit rate is low. Review cache strategy and TTL settings.'
      );
    }

    return {
      overall: {
        hitRate: stats.overallHitRate,
        totalRequests: stats.totalHits + stats.totalMisses,
        averageResponseTime: 0, // Would need timing data
      },
      layers: {
        L1: {
          hitRate: stats.layers.L1.hitRate,
          utilization: stats.layers.L1.utilization,
          size: stats.layers.L1.size,
        },
        L2: {
          hitRate: stats.layers.L2.hitRate,
          utilization: stats.layers.L2.utilization,
          size: stats.layers.L2.size,
        },
        L3: {
          hitRate: stats.layers.L3.hitRate,
          utilization: stats.layers.L3.utilization,
          size: stats.layers.L3.size,
        },
      },
      recommendations,
    };
  }

  /**
   * Get performance trends
   */
  getTrends(): {
    hitRateTrend: 'improving' | 'declining' | 'stable';
    utilizationTrend: 'increasing' | 'decreasing' | 'stable';
    recentStats: MultiLayerCacheStats[];
  } {
    if (this.statsHistory.length < 2) {
      return {
        hitRateTrend: 'stable',
        utilizationTrend: 'stable',
        recentStats: [],
      };
    }

    const recent = this.statsHistory.slice(-10);
    const older = this.statsHistory.slice(-20, -10);

    // Calculate average hit rates
    const recentHitRate = recent.reduce((sum, s) => sum + s.overallHitRate, 0) / recent.length;
    const olderHitRate =
      older.length > 0
        ? older.reduce((sum, s) => sum + s.overallHitRate, 0) / older.length
        : recentHitRate;

    const hitRateDiff = recentHitRate - olderHitRate;
    let hitRateTrend: 'improving' | 'declining' | 'stable' = 'stable';
    if (hitRateDiff > 0.05) {
      hitRateTrend = 'improving';
    } else if (hitRateDiff < -0.05) {
      hitRateTrend = 'declining';
    }

    // Calculate utilization trends
    const recentUtilization =
      recent.reduce((sum, s) => sum + s.layers.L1.utilization + s.layers.L2.utilization, 0) /
      (recent.length * 2);
    const olderUtilization =
      older.length > 0
        ? older.reduce((sum, s) => sum + s.layers.L1.utilization + s.layers.L2.utilization, 0) /
          (older.length * 2)
        : recentUtilization;

    const utilizationDiff = recentUtilization - olderUtilization;
    let utilizationTrend: 'increasing' | 'decreasing' | 'stable' = 'stable';
    if (utilizationDiff > 0.05) {
      utilizationTrend = 'increasing';
    } else if (utilizationDiff < -0.05) {
      utilizationTrend = 'decreasing';
    }

    return {
      hitRateTrend,
      utilizationTrend,
      recentStats: recent,
    };
  }

  /**
   * Generate cache performance report
   */
  generateReport(stats: MultiLayerCacheStats): string {
    const summary = this.getSummary(stats);
    const trends = this.getTrends();
    const uptime = Date.now() - this.startTime;

    const report = [
      'Cache Performance Report',
      '======================',
      '',
      `Uptime: ${Math.floor(uptime / 1000)}s`,
      '',
      'Overall Statistics:',
      `  Hit Rate: ${(summary.overall.hitRate * 100).toFixed(2)}%`,
      `  Total Requests: ${summary.overall.totalRequests}`,
      '',
      'Layer Statistics:',
      `  L1 (Memory):`,
      `    Hit Rate: ${((summary.layers['L1']?.hitRate || 0) * 100).toFixed(2)}%`,
      `    Utilization: ${((summary.layers['L1']?.utilization || 0) * 100).toFixed(2)}%`,
      `    Size: ${summary.layers['L1']?.size || 0} items`,
      `  L2 (File):`,
      `    Hit Rate: ${((summary.layers['L2']?.hitRate || 0) * 100).toFixed(2)}%`,
      `    Utilization: ${((summary.layers['L2']?.utilization || 0) * 100).toFixed(2)}%`,
      `    Size: ${summary.layers['L2']?.size || 0} items`,
      `  L3 (Redis):`,
      `    Hit Rate: ${((summary.layers['L3']?.hitRate || 0) * 100).toFixed(2)}%`,
      `    Utilization: ${((summary.layers['L3']?.utilization || 0) * 100).toFixed(2)}%`,
      `    Size: ${summary.layers['L3']?.size || 0} items`,
      '',
      'Trends:',
      `  Hit Rate: ${trends.hitRateTrend}`,
      `  Utilization: ${trends.utilizationTrend}`,
      '',
    ];

    if (summary.recommendations.length > 0) {
      report.push('Recommendations:');
      summary.recommendations.forEach((rec) => {
        report.push(`  - ${rec}`);
      });
    }

    return report.join('\n');
  }

  /**
   * Log cache statistics
   */
  logStats(stats: MultiLayerCacheStats, verbose = false): void {
    if (verbose) {
      logger.info(this.generateReport(stats));
    } else {
      logger.debug(
        `Cache stats: ${(stats.overallHitRate * 100).toFixed(2)}% hit rate, ` +
          `${stats.totalHits} hits, ${stats.totalMisses} misses`
      );
    }
  }

  /**
   * Reset analytics
   */
  reset(): void {
    this.statsHistory = [];
    this.startTime = Date.now();
  }
}

/**
 * Global cache analytics instance
 */
let globalCacheAnalytics: CacheAnalytics | null = null;

/**
 * Get or create global cache analytics instance
 */
export function getCacheAnalytics(): CacheAnalytics {
  if (!globalCacheAnalytics) {
    globalCacheAnalytics = new CacheAnalytics();
  }
  return globalCacheAnalytics;
}
