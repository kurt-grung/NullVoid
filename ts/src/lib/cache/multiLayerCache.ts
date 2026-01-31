/**
 * Multi-Layer Cache Implementation
 * L1: Memory (LRU), L2: File, L3: Redis (optional)
 */

import type {
  CacheLayer,
  CacheOperationResult,
  CachePromotionStrategy,
  MultiLayerCacheStats,
  LayerCacheStats,
} from '../../types/cache-types';
import { LRUCache } from '../cache';
import { CACHE_LAYER_CONFIG } from '../config';
import { logger } from '../logger';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

/**
 * Multi-layer cache implementation
 */
export class MultiLayerCache<T = unknown> {
  private l1Cache: LRUCache<T>;
  private l2Enabled: boolean;
  private l2CacheDir: string;
  private promotionStrategy: CachePromotionStrategy;
  private stats: {
    l1: LayerCacheStats;
    l2: LayerCacheStats;
  };

  constructor() {
    // Initialize L1 cache
    this.l1Cache = new LRUCache<T>({
      maxSize: CACHE_LAYER_CONFIG.L1.maxSize,
      defaultTTL: CACHE_LAYER_CONFIG.L1.defaultTTL,
      cleanupInterval: CACHE_LAYER_CONFIG.L1.cleanupInterval,
    });

    // Initialize L2 cache
    this.l2Enabled = CACHE_LAYER_CONFIG.L2.enabled;
    this.l2CacheDir = CACHE_LAYER_CONFIG.L2.cacheDir;

    // Ensure L2 cache directory exists
    if (this.l2Enabled) {
      try {
        if (!fs.existsSync(this.l2CacheDir)) {
          fs.mkdirSync(this.l2CacheDir, { recursive: true });
        }
      } catch (error) {
        logger.warn(`Failed to create L2 cache directory: ${error}`, {});
        this.l2Enabled = false;
      }
    }

    // Set promotion strategy
    this.promotionStrategy = CACHE_LAYER_CONFIG.PROMOTION_STRATEGY;

    // Initialize stats
    this.stats = {
      l1: this.createEmptyStats('L1'),
      l2: this.createEmptyStats('L2'),
    };
  }

  /**
   * Get value from cache (checks L1, then L2)
   */
  async get(key: string): Promise<CacheOperationResult<T>> {
    // Check L1 first
    const l1Value = this.l1Cache.get(key);
    if (l1Value !== null) {
      this.stats.l1.hits++;
      this.updateHitRate('L1');
      return {
        success: true,
        value: l1Value,
        layer: 'L1',
      };
    }
    this.stats.l1.misses++;

    // Check L2 if enabled
    if (this.l2Enabled) {
      try {
        const l2Value = await this.getFromL2(key);
        if (l2Value !== null) {
          this.stats.l2.hits++;
          this.updateHitRate('L2');

          // Promote to L1 based on strategy
          if (this.shouldPromoteToL1(key)) {
            this.l1Cache.set(key, l2Value);
          }

          return {
            success: true,
            value: l2Value,
            layer: 'L2',
          };
        }
        this.stats.l2.misses++;
      } catch (error) {
        logger.warn(`L2 cache read error for key ${key}`, { error: String(error) });
      }
    }

    this.updateHitRate('L1');
    this.updateHitRate('L2');

    return {
      success: false,
      layer: 'L1',
    };
  }

  /**
   * Set value in cache (stores in L1, optionally promotes to L2)
   */
  async set(key: string, value: T, ttl?: number): Promise<CacheOperationResult<T>> {
    // Always set in L1
    const l1TTL = ttl || CACHE_LAYER_CONFIG.L1.defaultTTL;
    this.l1Cache.set(key, value, l1TTL);

    // Optionally set in L2 based on promotion strategy
    if (this.l2Enabled && this.shouldPromoteToL2(key)) {
      try {
        await this.setToL2(key, value, ttl || CACHE_LAYER_CONFIG.L2.defaultTTL);
      } catch (error) {
        logger.warn(`L2 cache write error for key ${key}`, { error: String(error) });
      }
    }

    return {
      success: true,
      value,
      layer: 'L1',
    };
  }

  /**
   * Delete value from all cache layers
   */
  async delete(key: string): Promise<boolean> {
    const l1Deleted = this.l1Cache.delete(key);

    if (this.l2Enabled) {
      try {
        await this.deleteFromL2(key);
      } catch (error) {
        logger.warn(`L2 cache delete error for key ${key}`, {
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }

    return l1Deleted;
  }

  /**
   * Clear all cache layers
   */
  async clear(): Promise<void> {
    this.l1Cache.clear();

    if (this.l2Enabled) {
      try {
        const files = fs.readdirSync(this.l2CacheDir);
        for (const file of files) {
          const filePath = path.join(this.l2CacheDir, file);
          try {
            fs.unlinkSync(filePath);
          } catch (error) {
            logger.warn(`Failed to delete L2 cache file ${file}`, { error: String(error) });
          }
        }
      } catch (error) {
        logger.warn(`Failed to clear L2 cache`, { error: String(error) });
      }
    }

    // Reset stats
    this.stats.l1 = this.createEmptyStats('L1');
    this.stats.l2 = this.createEmptyStats('L2');
  }

  /**
   * Get cache statistics
   */
  getStats(): MultiLayerCacheStats {
    const l1Stats = this.l1Cache.getStats();
    this.stats.l1.size = l1Stats.size;
    this.stats.l1.maxSize = l1Stats.maxSize;
    this.stats.l1.evictions = l1Stats.evictions;

    // Calculate L2 stats
    if (this.l2Enabled) {
      try {
        const files = fs.readdirSync(this.l2CacheDir);
        this.stats.l2.size = files.length;
        this.stats.l2.maxSize = Math.floor(CACHE_LAYER_CONFIG.L2.maxSize / (100 * 1024)); // Estimate
        this.stats.l2.utilization = this.stats.l2.size / this.stats.l2.maxSize;
      } catch {
        // Ignore errors
      }
    }

    const totalHits = this.stats.l1.hits + this.stats.l2.hits;
    const totalMisses = this.stats.l1.misses + this.stats.l2.misses;
    const overallHitRate = totalHits + totalMisses > 0 ? totalHits / (totalHits + totalMisses) : 0;

    return {
      layers: {
        L1: { ...this.stats.l1 },
        L2: { ...this.stats.l2 },
        L3: this.createEmptyStats('L3'), // L3 not implemented yet
      },
      totalHits,
      totalMisses,
      overallHitRate,
      warming: false,
    };
  }

  /**
   * Get value from L2 (file cache)
   */
  private async getFromL2(key: string): Promise<T | null> {
    const filePath = this.getL2FilePath(key);

    try {
      if (!fs.existsSync(filePath)) {
        return null;
      }

      const data = fs.readFileSync(filePath, 'utf8');
      const entry = JSON.parse(data) as { value: T; expires: number };

      // Check expiration
      if (Date.now() > entry.expires) {
        fs.unlinkSync(filePath);
        return null;
      }

      return entry.value;
    } catch (error) {
      logger.debug(`L2 cache read error`, { error: String(error) });
      return null;
    }
  }

  /**
   * Set value to L2 (file cache)
   */
  private async setToL2(key: string, value: T, ttl: number): Promise<void> {
    const filePath = this.getL2FilePath(key);

    try {
      const entry = {
        value,
        expires: Date.now() + ttl,
      };

      fs.writeFileSync(filePath, JSON.stringify(entry), 'utf8');
    } catch (error) {
      logger.debug(`L2 cache write error`, { error: String(error) });
      throw error;
    }
  }

  /**
   * Delete value from L2 (file cache)
   */
  private async deleteFromL2(key: string): Promise<void> {
    const filePath = this.getL2FilePath(key);

    try {
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
    } catch (error) {
      logger.debug(`L2 cache delete error`, { error: String(error) });
    }
  }

  /**
   * Get L2 file path for key
   */
  private getL2FilePath(key: string): string {
    // Hash key to create safe filename
    const hash = crypto.createHash('sha256').update(key).digest('hex');
    return path.join(this.l2CacheDir, `${hash}.json`);
  }

  /**
   * Check if key should be promoted to L2
   */
  private shouldPromoteToL2(_key: string): boolean {
    // Simple strategy: promote if accessed multiple times
    // In a full implementation, we'd track access counts
    return this.promotionStrategy.timeBasedPromotion;
  }

  /**
   * Check if key should be promoted to L1
   */
  private shouldPromoteToL1(_key: string): boolean {
    // Promote from L2 to L1 if accessed
    return true;
  }

  /**
   * Update hit rate for layer
   */
  private updateHitRate(layer: CacheLayer): void {
    const stats = this.stats[layer.toLowerCase() as 'l1' | 'l2'];
    const total = stats.hits + stats.misses;
    if (total > 0) {
      stats.hitRate = stats.hits / total;
      stats.missRate = stats.misses / total;
    }
  }

  /**
   * Create empty stats for layer
   */
  private createEmptyStats(layer: CacheLayer): LayerCacheStats {
    return {
      layer,
      size: 0,
      maxSize: 0,
      hits: 0,
      misses: 0,
      evictions: 0,
      hitRate: 0,
      missRate: 0,
      utilization: 0,
    };
  }
}
