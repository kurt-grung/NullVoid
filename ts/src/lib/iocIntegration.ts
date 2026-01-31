/**
 * IoC (Indicators of Compromise) Integration Module
 * Centralized module for all IoC feed integrations
 */

import type {
  IoCProvider,
  IoCProviderName,
  IoCProviderConfig,
  IoCQueryOptions,
  IoCResponse,
  IoCResult,
  AggregatedIoCResults,
  ProviderRegistryEntry,
  IoCProviderFactory,
} from '../types/ioc-types';
import type { MultiLayerCacheStats } from '../types/cache-types';
import { LRUCache } from './cache';
import { MultiLayerCache } from './cache/multiLayerCache';
import { getCacheAnalytics } from './cache/cacheAnalytics';
import { IOC_CONFIG } from './config';
import { logger } from './logger';
import { RateLimiter } from './rateLimiter';

/**
 * Provider registry for IoC providers
 */
class ProviderRegistry {
  private providers: Map<IoCProviderName, ProviderRegistryEntry> = new Map();

  /**
   * Register a provider
   */
  register(entry: ProviderRegistryEntry): void {
    this.providers.set(entry.name, entry);
    logger.debug(`Registered IoC provider: ${entry.name}`);
  }

  /**
   * Get provider factory
   */
  getFactory(name: IoCProviderName): IoCProviderFactory | undefined {
    return this.providers.get(name)?.factory;
  }

  /**
   * Get default config for provider
   */
  getDefaultConfig(name: IoCProviderName): IoCProviderConfig | undefined {
    return this.providers.get(name)?.defaultConfig;
  }

  /**
   * Get all registered provider names
   */
  getRegisteredProviders(): IoCProviderName[] {
    return Array.from(this.providers.keys());
  }
}

/**
 * Global provider registry instance
 */
const providerRegistry = new ProviderRegistry();

/** Cache backend: either single LRU or multi-layer (L1+L2, optional L3) */
type IoCCacheBackend = LRUCache<IoCResponse> | MultiLayerCache<IoCResponse>;

/**
 * IoC Integration Manager
 * Manages all IoC providers, caching, rate limiting, and result aggregation
 */
export class IoCIntegrationManager {
  private providers: Map<IoCProviderName, IoCProvider> = new Map();
  private cache: IoCCacheBackend;
  private readonly useMultiLayer: boolean;
  private rateLimiters: Map<IoCProviderName, RateLimiter> = new Map();

  constructor() {
    this.useMultiLayer = IOC_CONFIG.USE_MULTI_LAYER_CACHE;
    if (this.useMultiLayer) {
      this.cache = new MultiLayerCache<IoCResponse>();
    } else {
      this.cache = new LRUCache<IoCResponse>({
        maxSize: 10000,
        defaultTTL: 60 * 60 * 1000, // 1 hour
        cleanupInterval: 5 * 60 * 1000, // 5 minutes
      });
    }
  }

  /**
   * Register a provider
   */
  registerProvider(provider: IoCProvider): void {
    this.providers.set(provider.name, provider);

    // Initialize rate limiter for provider
    const rateLimiter = new RateLimiter({
      maxRequests: provider.config.rateLimit,
      windowSize: 60 * 1000, // 1 minute window
    });
    this.rateLimiters.set(provider.name, rateLimiter);

    logger.info(`Registered IoC provider: ${provider.name}`);
  }

  /**
   * Query a single provider
   */
  async queryProvider(
    providerName: IoCProviderName,
    options: IoCQueryOptions
  ): Promise<IoCResponse | null> {
    const provider = this.providers.get(providerName);
    if (!provider) {
      logger.warn(`Provider ${providerName} not registered`);
      return null;
    }

    if (!provider.isAvailable()) {
      logger.debug(`Provider ${providerName} is not available`);
      return null;
    }

    // Check cache first
    const cacheKey = this.getCacheKey(providerName, options);
    if (this.useMultiLayer) {
      const result = await (this.cache as MultiLayerCache<IoCResponse>).get(cacheKey);
      const value = result.success ? result.value : undefined;
      if (value) {
        logger.debug(`Cache hit for ${providerName}:${options.packageName}`);
        return {
          ...value,
          metadata: {
            ...value.metadata,
            fromCache: true,
          },
        };
      }
    } else {
      const cached = (this.cache as LRUCache<IoCResponse>).get(cacheKey);
      if (cached) {
        logger.debug(`Cache hit for ${providerName}:${options.packageName}`);
        return {
          ...cached,
          metadata: {
            ...cached.metadata,
            fromCache: true,
          },
        };
      }
    }

    // Check rate limit and wait if needed
    const rateLimiter = this.rateLimiters.get(providerName);
    if (rateLimiter) {
      if (!rateLimiter.isAllowed()) {
        // Wait for rate limit to reset
        await rateLimiter.waitForReset();
      }
    }

    // Query provider
    const startTime = Date.now();
    try {
      const response = await provider.query(options);
      const responseTime = Date.now() - startTime;

      // Update metadata
      response.metadata = {
        ...response.metadata,
        responseTime,
        fromCache: false,
      };

      // Cache result
      const ttl = provider.config.cacheTTL;
      if (this.useMultiLayer) {
        await (this.cache as MultiLayerCache<IoCResponse>).set(cacheKey, response, ttl);
      } else {
        this.cache.set(cacheKey, response, ttl);
      }

      logger.debug(`Queried ${providerName} for ${options.packageName} in ${responseTime}ms`);
      return response;
    } catch (error) {
      const responseTime = Date.now() - startTime;
      const errorMessage = error instanceof Error ? error.message : String(error);

      // Check if it's a rate limit error (403, 429)
      const isRateLimitError =
        errorMessage.includes('403') ||
        errorMessage.includes('429') ||
        errorMessage.includes('rate limit') ||
        errorMessage.includes('Too Many Requests');

      if (isRateLimitError) {
        // Log rate limit errors at debug level to reduce noise
        logger.debug(`Rate limit hit for ${providerName}:${options.packageName}`, {
          error: errorMessage,
        });

        // Block the rate limiter for a longer period when we hit API rate limits
        if (rateLimiter) {
          // Block for 1 hour for GHSA (403), 6 seconds for NVD (429)
          const blockTime = errorMessage.includes('403') ? 3600000 : 6000;
          rateLimiter.blockedUntil = Date.now() + blockTime;
        }
      } else {
        // Log other errors normally
        logger.error(`Error querying ${providerName}`, { error: errorMessage });
      }

      return {
        results: [],
        metadata: {
          provider: providerName,
          timestamp: Date.now(),
          responseTime,
          fromCache: false,
          error: errorMessage,
        },
      };
    }
  }

  /**
   * Query all enabled providers and aggregate results
   */
  async queryAll(
    options: IoCQueryOptions,
    providerNames?: IoCProviderName[]
  ): Promise<AggregatedIoCResults> {
    const providersToQuery = providerNames || Array.from(this.providers.keys());
    const results: IoCResult[] = [];
    const providerStats: AggregatedIoCResults['providerStats'] =
      {} as AggregatedIoCResults['providerStats'];

    // Query all providers with a small delay between requests to avoid hitting rate limits
    const queries = providersToQuery.map(async (providerName, index) => {
      // Add a small delay between requests (100ms per provider)
      if (index > 0) {
        await new Promise((resolve) => setTimeout(resolve, 100 * index));
      }

      const startTime = Date.now();
      const queried = true;

      try {
        const response = await this.queryProvider(providerName, options);
        const responseTime = Date.now() - startTime;

        if (response) {
          results.push(...response.results);
          providerStats[providerName] = {
            queried,
            success: !response.metadata.error,
            resultCount: response.results.length,
            responseTime,
            ...(response.metadata.error ? { error: response.metadata.error } : {}),
          };
        } else {
          providerStats[providerName] = {
            queried,
            success: false,
            resultCount: 0,
            responseTime,
            error: 'Provider not available',
          };
        }
      } catch (error) {
        const responseTime = Date.now() - startTime;
        providerStats[providerName] = {
          queried,
          success: false,
          resultCount: 0,
          responseTime,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    });

    await Promise.allSettled(queries);

    // Group results by package
    const byPackage: Record<string, IoCResult[]> = {};
    for (const result of results) {
      const key = `${result.packageName}@${result.version}`;
      if (!byPackage[key]) {
        byPackage[key] = [];
      }
      byPackage[key]!.push(result);
    }

    // Get unique vulnerability IDs
    const uniqueVulnerabilities = Array.from(new Set(results.map((r) => r.vulnerabilityId)));

    return {
      byPackage,
      providerStats,
      totalResults: results.length,
      uniqueVulnerabilities,
    };
  }

  /**
   * Get cache key for provider query
   */
  private getCacheKey(providerName: IoCProviderName, options: IoCQueryOptions): string {
    return `${providerName}:${options.packageName}:${options.version || 'latest'}`;
  }

  /**
   * Clear cache for a specific package/provider (or all). Async when using multi-layer cache.
   */
  async clearCache(providerName?: IoCProviderName, packageName?: string): Promise<void> {
    if (this.useMultiLayer) {
      await (this.cache as MultiLayerCache<IoCResponse>).clear();
      return;
    }
    const lruCache = this.cache as LRUCache<IoCResponse>;
    if (providerName && packageName) {
      const keys = lruCache.keys();
      const prefix = `${providerName}:${packageName}:`;
      for (const key of keys) {
        if (key.startsWith(prefix)) {
          lruCache.delete(key);
        }
      }
    } else if (providerName) {
      const keys = lruCache.keys();
      const prefix = `${providerName}:`;
      for (const key of keys) {
        if (key.startsWith(prefix)) {
          lruCache.delete(key);
        }
      }
    } else {
      lruCache.clear();
    }
  }

  /**
   * Get cache statistics (LRU CacheStats or MultiLayerCacheStats when using multi-layer cache)
   */
  getCacheStats(): ReturnType<LRUCache<IoCResponse>['getStats']> | MultiLayerCacheStats {
    if (this.useMultiLayer) {
      const stats = (this.cache as MultiLayerCache<IoCResponse>).getStats();
      getCacheAnalytics().recordStats(stats);
      return stats;
    }
    return (this.cache as LRUCache<IoCResponse>).getStats();
  }

  /**
   * Get provider health status
   */
  async getProviderHealth(
    providerName: IoCProviderName
  ): Promise<{ healthy: boolean; message?: string }> {
    const provider = this.providers.get(providerName);
    if (!provider) {
      return { healthy: false, message: 'Provider not registered' };
    }

    try {
      return await provider.getHealth();
    } catch (error) {
      return {
        healthy: false,
        message: error instanceof Error ? error.message : String(error),
      };
    }
  }

  /**
   * Get all provider health statuses
   */
  async getAllProviderHealth(): Promise<
    Record<IoCProviderName, { healthy: boolean; message?: string }>
  > {
    const health: Record<string, { healthy: boolean; message?: string }> = {};

    for (const providerName of this.providers.keys()) {
      health[providerName] = await this.getProviderHealth(providerName);
    }

    return health as Record<IoCProviderName, { healthy: boolean; message?: string }>;
  }
}

/**
 * Global IoC integration manager instance
 */
let globalIoCManager: IoCIntegrationManager | null = null;

/**
 * Get or create global IoC integration manager
 */
export function getIoCManager(): IoCIntegrationManager {
  if (!globalIoCManager) {
    globalIoCManager = new IoCIntegrationManager();
  }
  return globalIoCManager;
}

/**
 * Register a provider factory in the global registry
 */
export function registerIoCProvider(entry: ProviderRegistryEntry): void {
  providerRegistry.register(entry);
}

/**
 * Get provider factory from registry
 */
export function getProviderFactory(name: IoCProviderName): IoCProviderFactory | undefined {
  return providerRegistry.getFactory(name);
}

/**
 * Get default config for provider
 */
export function getProviderDefaultConfig(name: IoCProviderName): IoCProviderConfig | undefined {
  return providerRegistry.getDefaultConfig(name);
}
