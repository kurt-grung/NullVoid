/**
 * LRU Cache Implementation for NullVoid
 * Provides efficient caching with size limits and TTL support
 * Migrated from JavaScript to TypeScript with enhanced type safety
 */

import { CACHE_CONFIG } from './config';

/**
 * Cache node for doubly linked list implementation
 */
export class CacheNode<T = unknown> {
  public key: string;
  public value: T;
  public ttl: number;
  public createdAt: number;
  public next: CacheNode<T> | null;
  public prev: CacheNode<T> | null;

  constructor(key: string, value: T, ttl: number = CACHE_CONFIG.TTL) {
    this.key = key;
    this.value = value;
    this.ttl = ttl;
    this.createdAt = Date.now();
    this.next = null;
    this.prev = null;
  }

  /**
   * Check if the cache node has expired
   * @returns True if expired
   */
  isExpired(): boolean {
    return Date.now() - this.createdAt > this.ttl;
  }
}

/**
 * Cache configuration options
 */
export interface CacheOptions {
  /** Maximum number of items in cache */
  maxSize?: number;
  /** Default TTL in milliseconds */
  defaultTTL?: number;
  /** Cleanup interval in milliseconds */
  cleanupInterval?: number;
}

/**
 * Cache statistics
 */
export interface CacheStats {
  /** Current cache size */
  size: number;
  /** Maximum cache size */
  maxSize: number;
  /** Number of cache hits */
  hits: number;
  /** Number of cache misses */
  misses: number;
  /** Number of evictions */
  evictions: number;
  /** Hit rate (0-1) */
  hitRate: number;
  /** Miss rate (0-1) */
  missRate: number;
}

/**
 * LRU Cache implementation with TypeScript generics
 */
export class LRUCache<T = unknown> {
  private maxSize: number;
  private defaultTTL: number;
  private cleanupInterval: number;
  private cache: Map<string, CacheNode<T>>;
  private head: CacheNode<T>;
  private tail: CacheNode<T>;
  private hits: number;
  private misses: number;
  private evictions: number;
  private cleanupTimer: ReturnType<typeof setTimeout> | null;

  constructor(options: CacheOptions = {}) {
    this.maxSize = options.maxSize || CACHE_CONFIG.MAX_SIZE;
    this.defaultTTL = options.defaultTTL || CACHE_CONFIG.TTL;
    this.cleanupInterval = options.cleanupInterval || CACHE_CONFIG.CLEANUP_INTERVAL;
    
    this.cache = new Map();
    this.head = new CacheNode<T>('', null as T);
    this.tail = new CacheNode<T>('', null as T);
    this.head.next = this.tail;
    this.tail.prev = this.head;
    
    this.hits = 0;
    this.misses = 0;
    this.evictions = 0;
    this.cleanupTimer = null;
    
    // Start cleanup interval
    this.startCleanup();
  }

  /**
   * Get value from cache
   * @param key - Cache key
   * @returns Cached value or null if not found/expired
   */
  get(key: string): T | null {
    const node = this.cache.get(key);
    
    if (!node) {
      this.misses++;
      return null;
    }
    
    if (node.isExpired()) {
      this.delete(key);
      this.misses++;
      return null;
    }
    
    // Move to head (most recently used)
    this.moveToHead(node);
    this.hits++;
    return node.value;
  }

  /**
   * Set value in cache
   * @param key - Cache key
   * @param value - Value to cache
   * @param ttl - Time to live in milliseconds
   * @returns True if set successfully
   */
  set(key: string, value: T, ttl: number = this.defaultTTL): boolean {
    // If key already exists, update it
    if (this.cache.has(key)) {
      const node = this.cache.get(key)!;
      node.value = value;
      node.ttl = ttl;
      node.createdAt = Date.now();
      this.moveToHead(node);
      return true;
    }
    
    // If cache is full, remove least recently used item
    if (this.cache.size >= this.maxSize) {
      this.evictLRU();
    }
    
    // Create new node and add to cache
    const newNode = new CacheNode<T>(key, value, ttl);
    this.cache.set(key, newNode);
    this.addToHead(newNode);
    
    return true;
  }

  /**
   * Delete value from cache
   * @param key - Cache key
   * @returns True if deleted
   */
  delete(key: string): boolean {
    const node = this.cache.get(key);
    if (!node) {
      return false;
    }
    
    this.cache.delete(key);
    this.removeNode(node);
    return true;
  }

  /**
   * Check if key exists in cache
   * @param key - Cache key
   * @returns True if exists and not expired
   */
  has(key: string): boolean {
    const node = this.cache.get(key);
    if (!node) {
      return false;
    }
    
    if (node.isExpired()) {
      this.delete(key);
      return false;
    }
    
    return true;
  }

  /**
   * Clear all cache entries
   */
  clear(): void {
    this.cache.clear();
    this.head.next = this.tail;
    this.tail.prev = this.head;
    this.hits = 0;
    this.misses = 0;
    this.evictions = 0;
  }

  /**
   * Get cache statistics
   * @returns Cache statistics
   */
  getStats(): CacheStats {
    const total = this.hits + this.misses;
    return {
      size: this.cache.size,
      maxSize: this.maxSize,
      hits: this.hits,
      misses: this.misses,
      evictions: this.evictions,
      hitRate: total > 0 ? this.hits / total : 0,
      missRate: total > 0 ? this.misses / total : 0
    };
  }

  /**
   * Get all cache keys
   * @returns Array of cache keys
   */
  keys(): string[] {
    return Array.from(this.cache.keys());
  }

  /**
   * Get all cache values
   * @returns Array of cache values
   */
  values(): T[] {
    return Array.from(this.cache.values()).map(node => node.value);
  }

  /**
   * Get cache size
   * @returns Current cache size
   */
  size(): number {
    return this.cache.size;
  }

  /**
   * Check if cache is empty
   * @returns True if cache is empty
   */
  isEmpty(): boolean {
    return this.cache.size === 0;
  }

  /**
   * Move node to head of the list
   * @param node - Node to move
   */
  private moveToHead(node: CacheNode<T>): void {
    this.removeNode(node);
    this.addToHead(node);
  }

  /**
   * Add node to head of the list
   * @param node - Node to add
   */
  private addToHead(node: CacheNode<T>): void {
    node.prev = this.head;
    node.next = this.head.next;
    this.head.next!.prev = node;
    this.head.next = node;
  }

  /**
   * Remove node from the list
   * @param node - Node to remove
   */
  private removeNode(node: CacheNode<T>): void {
    node.prev!.next = node.next;
    node.next!.prev = node.prev;
  }

  /**
   * Evict least recently used item
   */
  private evictLRU(): void {
    const lastNode = this.tail.prev!;
    if (lastNode !== this.head) {
      this.cache.delete(lastNode.key);
      this.removeNode(lastNode);
      this.evictions++;
    }
  }

  /**
   * Start cleanup interval to remove expired entries
   */
  private startCleanup(): void {
    if (this.cleanupInterval > 0) {
      this.cleanupTimer = setInterval(() => {
        this.cleanup();
      }, this.cleanupInterval);
      
      // Unref the timer so it doesn't keep the process alive
      if (this.cleanupTimer && this.cleanupTimer.unref) {
        this.cleanupTimer.unref();
      }
    }
  }

  /**
   * Stop cleanup interval
   */
  private stopCleanup(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
  }

  /**
   * Clean up expired entries
   */
  private cleanup(): void {
    const expiredKeys: string[] = [];
    
    for (const [key, node] of this.cache.entries()) {
      if (node.isExpired()) {
        expiredKeys.push(key);
      }
    }
    
    expiredKeys.forEach(key => this.delete(key));
  }

  /**
   * Destroy cache and cleanup resources
   */
  destroy(): void {
    this.stopCleanup();
    this.clear();
  }
}

/**
 * Package-specific cache implementation
 */
export class PackageCache<T = unknown> extends LRUCache<T> {
  constructor(options: CacheOptions = {}) {
    super({
      maxSize: options.maxSize || CACHE_CONFIG.MAX_SIZE,
      defaultTTL: options.defaultTTL || CACHE_CONFIG.TTL,
      cleanupInterval: options.cleanupInterval || CACHE_CONFIG.CLEANUP_INTERVAL
    });
  }

  /**
   * Get package analysis result
   * @param packageName - Package name
   * @param version - Package version
   * @returns Cached analysis result
   */
  getPackage(packageName: string, version: string): T | null {
    const key = `${packageName}@${version}`;
    return this.get(key);
  }

  /**
   * Set package analysis result
   * @param packageName - Package name
   * @param version - Package version
   * @param result - Analysis result
   * @param ttl - Time to live
   * @returns True if set successfully
   */
  setPackage(packageName: string, version: string, result: T, ttl?: number): boolean {
    const key = `${packageName}@${version}`;
    return this.set(key, result, ttl);
  }

  /**
   * Invalidate package cache
   * @param packageName - Package name
   * @param version - Package version (optional)
   * @returns True if invalidated
   */
  invalidatePackage(packageName: string, version?: string): boolean {
    if (version) {
      const key = `${packageName}@${version}`;
      return this.delete(key);
    } else {
      // Invalidate all versions of the package
      const keysToDelete = this.keys().filter(key => key.startsWith(`${packageName}@`));
      keysToDelete.forEach(key => this.delete(key));
      return keysToDelete.length > 0;
    }
  }

  /**
   * Get all packages for a given name
   * @param packageName - Package name
   * @returns Array of versions for the package
   */
  getPackageVersions(packageName: string): string[] {
    return this.keys()
      .filter(key => key.startsWith(`${packageName}@`))
      .map(key => key.split('@')[1])
      .filter((version): version is string => version !== undefined);
  }

  /**
   * Check if package exists in cache
   * @param packageName - Package name
   * @param version - Package version
   * @returns True if package exists and not expired
   */
  hasPackage(packageName: string, version: string): boolean {
    const key = `${packageName}@${version}`;
    return this.has(key);
  }

  /**
   * Get package cache statistics
   * @returns Package-specific cache statistics
   */
  getPackageStats(): CacheStats & { packages: number; versions: Record<string, number> } {
    const stats = this.getStats();
    const packages = new Set<string>();
    const versions: Record<string, number> = {};

    for (const key of this.keys()) {
      const parts = key.split('@');
      const packageName = parts[0];
      if (packageName) {
        packages.add(packageName);
        versions[packageName] = (versions[packageName] || 0) + 1;
      }
    }

    return {
      ...stats,
      packages: packages.size,
      versions
    };
  }
}
