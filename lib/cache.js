/**
 * LRU Cache Implementation for NullVoid
 * Provides efficient caching with size limits and TTL support
 */

const { CACHE_CONFIG } = require('./config');

/**
 * LRU Cache node
 */
class CacheNode {
  constructor(key, value, ttl = CACHE_CONFIG.TTL) {
    this.key = key;
    this.value = value;
    this.ttl = ttl;
    this.createdAt = Date.now();
    this.next = null;
    this.prev = null;
  }

  /**
   * Check if the cache node has expired
   * @returns {boolean} True if expired
   */
  isExpired() {
    return Date.now() - this.createdAt > this.ttl;
  }
}

/**
 * LRU Cache implementation
 */
class LRUCache {
  constructor(options = {}) {
    this.maxSize = options.maxSize || CACHE_CONFIG.MAX_SIZE;
    this.defaultTTL = options.defaultTTL || CACHE_CONFIG.TTL;
    this.cleanupInterval = options.cleanupInterval || CACHE_CONFIG.CLEANUP_INTERVAL;
    
    this.cache = new Map();
    this.head = new CacheNode(null, null);
    this.tail = new CacheNode(null, null);
    this.head.next = this.tail;
    this.tail.prev = this.head;
    
    this.hits = 0;
    this.misses = 0;
    this.evictions = 0;
    
    // Start cleanup interval
    this.startCleanup();
  }

  /**
   * Get value from cache
   * @param {string} key - Cache key
   * @returns {*} Cached value or null if not found/expired
   */
  get(key) {
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
   * @param {string} key - Cache key
   * @param {*} value - Value to cache
   * @param {number} ttl - Time to live in milliseconds
   * @returns {boolean} True if set successfully
   */
  set(key, value, ttl = this.defaultTTL) {
    // If key already exists, update it
    if (this.cache.has(key)) {
      const node = this.cache.get(key);
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
    const newNode = new CacheNode(key, value, ttl);
    this.cache.set(key, newNode);
    this.addToHead(newNode);
    
    return true;
  }

  /**
   * Delete value from cache
   * @param {string} key - Cache key
   * @returns {boolean} True if deleted
   */
  delete(key) {
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
   * @param {string} key - Cache key
   * @returns {boolean} True if exists and not expired
   */
  has(key) {
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
  clear() {
    this.cache.clear();
    this.head.next = this.tail;
    this.tail.prev = this.head;
    this.hits = 0;
    this.misses = 0;
    this.evictions = 0;
  }

  /**
   * Get cache statistics
   * @returns {object} Cache statistics
   */
  getStats() {
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
   * @returns {Array} Array of cache keys
   */
  keys() {
    return Array.from(this.cache.keys());
  }

  /**
   * Get all cache values
   * @returns {Array} Array of cache values
   */
  values() {
    return Array.from(this.cache.values()).map(node => node.value);
  }

  /**
   * Move node to head of the list
   * @param {CacheNode} node - Node to move
   */
  moveToHead(node) {
    this.removeNode(node);
    this.addToHead(node);
  }

  /**
   * Add node to head of the list
   * @param {CacheNode} node - Node to add
   */
  addToHead(node) {
    node.prev = this.head;
    node.next = this.head.next;
    this.head.next.prev = node;
    this.head.next = node;
  }

  /**
   * Remove node from the list
   * @param {CacheNode} node - Node to remove
   */
  removeNode(node) {
    node.prev.next = node.next;
    node.next.prev = node.prev;
  }

  /**
   * Evict least recently used item
   */
  evictLRU() {
    const lastNode = this.tail.prev;
    if (lastNode !== this.head) {
      this.cache.delete(lastNode.key);
      this.removeNode(lastNode);
      this.evictions++;
    }
  }

  /**
   * Start cleanup interval to remove expired entries
   */
  startCleanup() {
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
  stopCleanup() {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
  }

  /**
   * Clean up expired entries
   */
  cleanup() {
    const expiredKeys = [];
    
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
  destroy() {
    this.stopCleanup();
    this.clear();
  }
}

/**
 * Package-specific cache implementation
 */
class PackageCache extends LRUCache {
  constructor(options = {}) {
    super({
      maxSize: options.maxSize || CACHE_CONFIG.MAX_SIZE,
      defaultTTL: options.defaultTTL || CACHE_CONFIG.TTL,
      cleanupInterval: options.cleanupInterval || CACHE_CONFIG.CLEANUP_INTERVAL
    });
  }

  /**
   * Get package analysis result
   * @param {string} packageName - Package name
   * @param {string} version - Package version
   * @returns {*} Cached analysis result
   */
  getPackage(packageName, version) {
    const key = `${packageName}@${version}`;
    return this.get(key);
  }

  /**
   * Set package analysis result
   * @param {string} packageName - Package name
   * @param {string} version - Package version
   * @param {*} result - Analysis result
   * @param {number} ttl - Time to live
   * @returns {boolean} True if set successfully
   */
  setPackage(packageName, version, result, ttl) {
    const key = `${packageName}@${version}`;
    return this.set(key, result, ttl);
  }

  /**
   * Invalidate package cache
   * @param {string} packageName - Package name
   * @param {string} version - Package version (optional)
   * @returns {boolean} True if invalidated
   */
  invalidatePackage(packageName, version) {
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
}

module.exports = {
  LRUCache,
  PackageCache,
  CacheNode
};
