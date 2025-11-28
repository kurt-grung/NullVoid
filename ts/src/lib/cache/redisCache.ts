/**
 * Redis Cache Implementation (L3)
 * Optional distributed cache support with automatic failover
 */

import type { L3CacheConfig } from '../../types/cache-types';
import { CACHE_LAYER_CONFIG } from '../config';
import { logger } from '../logger';

/**
 * Redis client interface (to avoid requiring redis as a dependency)
 */
interface RedisClient {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, options?: { EX?: number }): Promise<string | null>;
  del(key: string): Promise<number>;
  exists(key: string): Promise<number>;
  ping(): Promise<string>;
  quit(): Promise<void>;
}

/**
 * Redis cache implementation
 * Gracefully handles when Redis is not available
 */
export class RedisCache {
  private config: L3CacheConfig;
  private client: RedisClient | null = null;
  private available = false;
  private connectionAttempts = 0;
  private readonly maxConnectionAttempts = 3;
  
  constructor(config?: Partial<L3CacheConfig>) {
    this.config = {
      layer: 'L3',
      ...CACHE_LAYER_CONFIG.L3,
      ...config
    } as L3CacheConfig;
    
    if (this.config.enabled) {
      this.initialize().catch(error => {
        logger.warn('Redis cache initialization failed, will use fallback', { error: String(error) });
      });
    }
  }
  
  /**
   * Initialize Redis connection
   */
  private async initialize(): Promise<void> {
    try {
      // Try to load redis module (optional dependency)
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const redis = require('redis');
      
      if (!redis) {
        throw new Error('Redis module not available');
      }
      
      // Create Redis client
      const clientOptions: Record<string, unknown> = {
        socket: {
          connectTimeout: this.config.connectTimeout || 5000
        }
      };
      
      const password = this.config['password'];
      if (password) {
        clientOptions['password'] = password;
      }
      
      const db = this.config['db'];
      if (db !== undefined) {
        clientOptions['database'] = db;
      }
      
      let client: RedisClient;
      
      if (this.config.redisUrl) {
        client = redis.createClient({ url: this.config.redisUrl, ...clientOptions });
      } else {
        client = redis.createClient({
          socket: {
            host: this.config.host || 'localhost',
            port: this.config.port || 6379,
            connectTimeout: this.config.connectTimeout || 5000
          },
          ...clientOptions
        });
      }
      
      // Handle connection events (if client supports event emitter)
      if (typeof (client as unknown as { on?: (event: string, handler: () => void) => void }).on === 'function') {
        (client as unknown as { on: (event: string, handler: (error?: Error) => void) => void }).on('error', (error?: Error) => {
          logger.warn('Redis connection error', { error: error?.message || String(error) });
          this.available = false;
        });
        
        (client as unknown as { on: (event: string, handler: () => void) => void }).on('connect', () => {
          logger.debug('Redis connected', {});
          this.available = true;
          this.connectionAttempts = 0;
        });
        
        (client as unknown as { on: (event: string, handler: () => void) => void }).on('ready', () => {
          logger.info('Redis cache ready', {});
          this.available = true;
        });
      }
      
      // Connect to Redis (if client has connect method)
      if (typeof (client as unknown as { connect?: () => Promise<void> }).connect === 'function') {
        await (client as unknown as { connect: () => Promise<void> }).connect();
      }
      
      // Test connection
      await client.ping();
      
      this.client = client;
      this.available = true;
      
      logger.info('Redis cache initialized successfully');
    } catch (error) {
      this.connectionAttempts++;
      
      if (this.connectionAttempts < this.maxConnectionAttempts) {
        logger.debug(`Redis connection attempt ${this.connectionAttempts} failed, will retry`);
        // Will retry on next operation
      } else {
        logger.warn('Redis cache unavailable, using fallback to L1/L2 cache');
        this.available = false;
        this.client = null;
      }
      
      throw error;
    }
  }
  
  /**
   * Get value from Redis
   */
  async get<T>(key: string): Promise<T | null> {
    if (!this.config.enabled || !this.available || !this.client) {
      return null;
    }
    
    try {
      const value = await this.client.get(key);
      if (value === null) {
        return null;
      }
      
      return JSON.parse(value) as T;
    } catch (error) {
      if (error) {
        logger.debug(`Redis get error for key ${key}`, { error: String(error) });
      }
      this.available = false;
      return null;
    }
  }
  
  /**
   * Set value in Redis
   */
  async set<T>(key: string, value: T, ttl?: number): Promise<boolean> {
    if (!this.config.enabled) {
      return false;
    }
    
    // Try to reconnect if not available
    if (!this.available || !this.client) {
      if (this.connectionAttempts < this.maxConnectionAttempts) {
        try {
          await this.initialize();
        } catch {
          return false;
        }
      } else {
        return false;
      }
    }
    
    try {
      const serialized = JSON.stringify(value);
      const ttlSeconds = ttl ? Math.floor(ttl / 1000) : undefined;
      
      if (this.client) {
        await this.client.set(key, serialized, ttlSeconds ? { EX: ttlSeconds } : undefined);
        return true;
      }
      return false;
    } catch (error) {
      logger.debug(`Redis set error for key ${key}`, { error: String(error) });
      this.available = false;
      return false;
    }
  }
  
  /**
   * Delete value from Redis
   */
  async delete(key: string): Promise<boolean> {
    if (!this.config.enabled || !this.available || !this.client) {
      return false;
    }
    
    try {
      const result = await this.client.del(key);
      return result > 0;
    } catch (error) {
      logger.debug(`Redis delete error for key ${key}`, { error: String(error) });
      this.available = false;
      return false;
    }
  }
  
  /**
   * Check if key exists in Redis
   */
  async exists(key: string): Promise<boolean> {
    if (!this.config.enabled || !this.available || !this.client) {
      return false;
    }
    
    try {
      const result = await this.client.exists(key);
      return result > 0;
    } catch (error) {
      logger.debug(`Redis exists error for key ${key}`, { error: String(error) });
      return false;
    }
  }
  
  /**
   * Check if Redis is available
   */
  isAvailable(): boolean {
    return this.config.enabled && this.available && this.client !== null;
  }
  
  /**
   * Get connection status
   */
  getStatus(): {
    enabled: boolean;
    available: boolean;
    connected: boolean;
    connectionAttempts: number;
  } {
    return {
      enabled: this.config.enabled,
      available: this.available,
      connected: this.client !== null && this.available,
      connectionAttempts: this.connectionAttempts
    };
  }
  
  /**
   * Close Redis connection
   */
  async close(): Promise<void> {
    if (this.client) {
      try {
        await this.client.quit();
        this.client = null;
        this.available = false;
        logger.debug('Redis connection closed');
      } catch (error) {
        logger.warn('Error closing Redis connection', { error: String(error) });
      }
    }
  }
}

/**
 * Create Redis cache instance
 */
export function createRedisCache(config?: Partial<L3CacheConfig>): RedisCache {
  return new RedisCache(config);
}

