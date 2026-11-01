/**
 * Memory Pool Tests
 */

import { describe, it, expect, beforeEach } from '@jest/globals';
import { MemoryPool, MemoryPoolManager, CommonObjectPools, getCommonObjectPools } from '../../src/lib/parallel/memoryPool';

describe('Memory Pool', () => {
  describe('MemoryPool', () => {
    let pool: MemoryPool<string>;

    beforeEach(() => {
      pool = new MemoryPool<string>({
        initialSize: 5,
        maxSize: 10,
        factory: () => 'pooled-object'
      });
    });

    it('should create pool instance', () => {
      expect(pool).toBeDefined();
    });

    it('should acquire and release objects', () => {
      const obj = pool.acquire();
      expect(obj).toBe('pooled-object');
      
      pool.release(obj);
      
      const stats = pool.getStats();
      expect(stats.poolSize).toBeGreaterThan(0);
    });

    it('should get pool statistics', () => {
      const stats = pool.getStats();
      
      expect(stats).toBeDefined();
      expect(typeof stats.poolSize).toBe('number');
      expect(typeof stats.allocated).toBe('number');
      expect(typeof stats.totalCreated).toBe('number');
      expect(typeof stats.utilization).toBe('number');
    });

    it('should clear pool', () => {
      pool.acquire();
      pool.clear();
      
      const stats = pool.getStats();
      expect(stats.allocated).toBe(0);
    });
  });

  describe('MemoryPoolManager', () => {
    let manager: MemoryPoolManager;

    beforeEach(() => {
      manager = new MemoryPoolManager();
    });

    it('should create manager instance', () => {
      expect(manager).toBeDefined();
    });

    it('should register and get pools', () => {
      const pool = manager.registerPool('test', {
        initialSize: 2,
        maxSize: 5,
        factory: () => ({})
      });
      
      expect(pool).toBeDefined();
      
      const retrieved = manager.getPool('test');
      expect(retrieved).toBe(pool);
    });

    it('should get all pool statistics', () => {
      manager.registerPool('test1', {
        initialSize: 2,
        maxSize: 5,
        factory: () => ({})
      });
      
      const stats = manager.getAllStats();
      expect(stats).toBeDefined();
      expect(stats['test1']).toBeDefined();
    });
  });

  describe('CommonObjectPools', () => {
    let pools: CommonObjectPools;

    beforeEach(() => {
      pools = new CommonObjectPools();
    });

    it('should create pools instance', () => {
      expect(pools).toBeDefined();
    });

    it('should acquire and release buffers', () => {
      const buffer = pools.acquireBuffer();
      expect(Buffer.isBuffer(buffer)).toBe(true);
      
      pools.releaseBuffer(buffer);
    });

    it('should acquire and release arrays', () => {
      const arr = pools.acquireArray<number>();
      expect(Array.isArray(arr)).toBe(true);
      
      pools.releaseArray(arr);
    });

    it('should acquire and release objects', () => {
      const obj = pools.acquireObject();
      expect(typeof obj).toBe('object');
      
      pools.releaseObject(obj);
    });

    it('should get statistics', () => {
      const stats = pools.getStats();
      expect(stats).toBeDefined();
    });

    it('should get global pools instance', () => {
      const globalPools = getCommonObjectPools();
      expect(globalPools).toBeDefined();
      expect(globalPools).toBeInstanceOf(CommonObjectPools);
    });
  });
});

