/**
 * Multi-Layer Cache Type Definitions
 */

/**
 * Cache layer identifiers
 */
export type CacheLayer = 'L1' | 'L2' | 'L3';

/**
 * Cache layer configuration
 */
export interface CacheLayerConfig {
  /** Layer identifier */
  layer: CacheLayer;
  /** Whether layer is enabled */
  enabled: boolean;
  /** Maximum size (items for L1, bytes for L2/L3) */
  maxSize: number;
  /** Default TTL in milliseconds */
  defaultTTL: number;
  /** Cleanup interval in milliseconds */
  cleanupInterval: number;
}

/**
 * L1 (Memory) cache configuration
 */
export interface L1CacheConfig extends CacheLayerConfig {
  layer: 'L1';
  /** Maximum number of items */
  maxSize: number;
}

/**
 * L2 (File) cache configuration
 */
export interface L2CacheConfig extends CacheLayerConfig {
  layer: 'L2';
  /** Cache directory path */
  cacheDir: string;
  /** Maximum cache size in bytes */
  maxSize: number;
  /** Compression enabled */
  compression?: boolean;
}

/**
 * L3 (Distributed/Redis) cache configuration
 */
export interface L3CacheConfig extends CacheLayerConfig {
  layer: 'L3';
  /** Redis connection URL */
  redisUrl?: string;
  /** Redis host */
  host?: string;
  /** Redis port */
  port?: number;
  /** Redis password */
  password?: string;
  /** Redis database number */
  db?: number;
  /** Connection pool size */
  poolSize?: number;
  /** Connection timeout */
  connectTimeout?: number;
}

/**
 * Cache operation result
 */
export interface CacheOperationResult<T> {
  /** Whether operation was successful */
  success: boolean;
  /** Cached value (if found) */
  value?: T;
  /** Layer where value was found */
  layer?: CacheLayer;
  /** Error message if failed */
  error?: string;
}

/**
 * Cache promotion/demotion strategy
 */
export interface CachePromotionStrategy {
  /** Promote to higher layer after N accesses */
  promoteAfterAccesses: number;
  /** Demote from higher layer after N misses */
  demoteAfterMisses: number;
  /** Time-based promotion (promote if accessed within TTL) */
  timeBasedPromotion: boolean;
}

/**
 * Cache statistics per layer
 */
export interface LayerCacheStats {
  /** Layer identifier */
  layer: CacheLayer;
  /** Current size */
  size: number;
  /** Maximum size */
  maxSize: number;
  /** Number of hits */
  hits: number;
  /** Number of misses */
  misses: number;
  /** Number of evictions */
  evictions: number;
  /** Hit rate (0-1) */
  hitRate: number;
  /** Miss rate (0-1) */
  missRate: number;
  /** Utilization (0-1) */
  utilization: number;
}

/**
 * Multi-layer cache statistics
 */
export interface MultiLayerCacheStats {
  /** Statistics per layer */
  layers: Record<CacheLayer, LayerCacheStats>;
  /** Total hits across all layers */
  totalHits: number;
  /** Total misses across all layers */
  totalMisses: number;
  /** Overall hit rate */
  overallHitRate: number;
  /** Cache warming status */
  warming: boolean;
}

/**
 * Cache entry metadata
 */
export interface CacheEntryMetadata {
  /** Layer where entry is stored */
  layer: CacheLayer;
  /** Creation timestamp */
  createdAt: number;
  /** Last access timestamp */
  lastAccessed: number;
  /** Access count */
  accessCount: number;
  /** TTL in milliseconds */
  ttl: number;
  /** Whether entry is expired */
  expired: boolean;
}

/**
 * Cache warming configuration
 */
export interface CacheWarmingConfig {
  /** Enable cache warming */
  enabled: boolean;
  /** Warm on startup */
  warmOnStartup: boolean;
  /** Preload patterns */
  preloadPatterns: string[];
  /** Warming strategy */
  strategy: 'aggressive' | 'conservative' | 'on-demand';
}

