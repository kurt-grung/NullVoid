/**
 * Memory Pool Management
 * Efficient memory allocation/deallocation with object pooling
 */

import { logger } from '../logger';

/**
 * Memory pool configuration
 */
export interface MemoryPoolConfig {
  /** Initial pool size */
  initialSize: number;
  /** Maximum pool size */
  maxSize: number;
  /** Object factory function */
  factory: () => unknown;
  /** Object reset function */
  reset?: (obj: unknown) => void;
}

/**
 * Memory pool implementation
 */
export class MemoryPool<T = unknown> {
  private config: MemoryPoolConfig;
  private pool: T[] = [];
  private allocated: Set<T> = new Set();
  private created = 0;
  
  constructor(config: MemoryPoolConfig) {
    this.config = config;
    this.initialize();
  }
  
  /**
   * Initialize pool with initial objects
   */
  private initialize(): void {
    for (let i = 0; i < this.config.initialSize; i++) {
      const obj = this.config.factory() as T;
      this.pool.push(obj);
      this.created++;
    }
  }
  
  /**
   * Acquire object from pool
   */
  acquire(): T {
    let obj: T;
    
    if (this.pool.length > 0) {
      // Reuse from pool
      obj = this.pool.pop()!;
    } else {
      // Create new object if pool is empty and under max size
      if (this.created < this.config.maxSize) {
        obj = this.config.factory() as T;
        this.created++;
      } else {
        // Pool exhausted, create temporary object
        logger.warn('Memory pool exhausted, creating temporary object');
        obj = this.config.factory() as T;
      }
    }
    
    this.allocated.add(obj);
    return obj;
  }
  
  /**
   * Release object back to pool
   */
  release(obj: T): void {
    if (!this.allocated.has(obj)) {
      logger.warn('Attempted to release object not from this pool');
      return;
    }
    
    this.allocated.delete(obj);
    
    // Reset object if reset function provided
    if (this.config.reset) {
      this.config.reset(obj);
    }
    
    // Return to pool if not at max size
    if (this.pool.length < this.config.maxSize) {
      this.pool.push(obj);
    }
    // Otherwise, let it be garbage collected
  }
  
  /**
   * Get pool statistics
   */
  getStats(): {
    poolSize: number;
    allocated: number;
    totalCreated: number;
    utilization: number;
  } {
    return {
      poolSize: this.pool.length,
      allocated: this.allocated.size,
      totalCreated: this.created,
      utilization: this.created > 0 ? this.allocated.size / this.created : 0
    };
  }
  
  /**
   * Clear pool
   */
  clear(): void {
    this.pool = [];
    this.allocated.clear();
    this.created = 0;
    this.initialize();
  }
}

/**
 * Memory pool manager for multiple pools
 */
export class MemoryPoolManager {
  private pools: Map<string, MemoryPool> = new Map();
  
  /**
   * Register a memory pool
   */
  registerPool(name: string, config: MemoryPoolConfig): MemoryPool {
    const pool = new MemoryPool(config);
    this.pools.set(name, pool);
    return pool;
  }
  
  /**
   * Get pool by name
   */
  getPool<T>(name: string): MemoryPool<T> | undefined {
    return this.pools.get(name) as MemoryPool<T> | undefined;
  }
  
  /**
   * Get all pool statistics
   */
  getAllStats(): Record<string, ReturnType<MemoryPool['getStats']>> {
    const stats: Record<string, ReturnType<MemoryPool['getStats']>> = {};
    
    for (const [name, pool] of this.pools.entries()) {
      stats[name] = pool.getStats();
    }
    
    return stats;
  }
  
  /**
   * Clear all pools
   */
  clearAll(): void {
    for (const pool of this.pools.values()) {
      pool.clear();
    }
  }
}

/**
 * Predefined object pools for common types
 */
export class CommonObjectPools {
  private manager: MemoryPoolManager;
  
  constructor() {
    this.manager = new MemoryPoolManager();
    
    // Register common pools
    this.initializeCommonPools();
  }
  
  /**
   * Initialize common object pools
   */
  private initializeCommonPools(): void {
    // Buffer pool
    this.manager.registerPool('buffer', {
      initialSize: 10,
      maxSize: 100,
      factory: () => Buffer.alloc(1024),
      reset: (buf) => {
        if (Buffer.isBuffer(buf)) {
          buf.fill(0);
        }
      }
    });
    
    // Array pool
    this.manager.registerPool('array', {
      initialSize: 20,
      maxSize: 200,
      factory: () => [],
      reset: (arr) => {
        if (Array.isArray(arr)) {
          arr.length = 0;
        }
      }
    });
    
    // Object pool
    this.manager.registerPool('object', {
      initialSize: 20,
      maxSize: 200,
      factory: () => ({}),
      reset: (obj) => {
        if (typeof obj === 'object' && obj !== null) {
          for (const key in obj) {
            delete (obj as Record<string, unknown>)[key];
          }
        }
      }
    });
  }
  
  /**
   * Get buffer from pool
   */
  acquireBuffer(): Buffer {
    const pool = this.manager.getPool<Buffer>('buffer');
    return pool ? pool.acquire() : Buffer.alloc(1024);
  }
  
  /**
   * Release buffer to pool
   */
  releaseBuffer(buffer: Buffer): void {
    const pool = this.manager.getPool<Buffer>('buffer');
    if (pool) {
      pool.release(buffer);
    }
  }
  
  /**
   * Get array from pool
   */
  acquireArray<T>(): T[] {
    const pool = this.manager.getPool<T[]>('array');
    return pool ? pool.acquire() : [];
  }
  
  /**
   * Release array to pool
   */
  releaseArray<T>(arr: T[]): void {
    const pool = this.manager.getPool<T[]>('array');
    if (pool) {
      pool.release(arr);
    }
  }
  
  /**
   * Get object from pool
   */
  acquireObject(): Record<string, unknown> {
    const pool = this.manager.getPool<Record<string, unknown>>('object');
    return pool ? pool.acquire() : {};
  }
  
  /**
   * Release object to pool
   */
  releaseObject(obj: Record<string, unknown>): void {
    const pool = this.manager.getPool<Record<string, unknown>>('object');
    if (pool) {
      pool.release(obj);
    }
  }
  
  /**
   * Get all statistics
   */
  getStats(): ReturnType<MemoryPoolManager['getAllStats']> {
    return this.manager.getAllStats();
  }
  
  /**
   * Clear all pools
   */
  clear(): void {
    this.manager.clearAll();
  }
}

/**
 * Global common object pools instance
 */
let globalCommonPools: CommonObjectPools | null = null;

/**
 * Get or create global common object pools
 */
export function getCommonObjectPools(): CommonObjectPools {
  if (!globalCommonPools) {
    globalCommonPools = new CommonObjectPools();
  }
  return globalCommonPools;
}

