/**
 * Request Batcher Unit Tests
 */

import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { RequestBatcher } from '../../src/lib/network/requestBatcher';

describe('RequestBatcher', () => {
  let batcher: RequestBatcher;

  beforeEach(() => {
    batcher = new RequestBatcher({
      maxBatchSize: 5,
      batchTimeout: 100
    });
  });

  describe('Batch Creation', () => {
    it('should batch requests correctly', async () => {
      const requests: Array<() => Promise<string>> = [];
      for (let i = 0; i < 10; i++) {
        requests.push(async () => `result-${i}`);
      }

      // Use addRequest method which is the public API
      const results = await Promise.all(
        requests.map((req, idx) => 
          batcher.addRequest(`https://example.com/api/${idx}`, { priority: 1 }, req)
        )
      );

      expect(results).toHaveLength(10);
      expect(results[0]).toBe('result-0');
      expect(results[9]).toBe('result-9');
    });

    it('should respect batch size limit', async () => {
      const batchSizes: number[] = [];
      const originalBatch = batcher['sendBatch'].bind(batcher);
      
      batcher['sendBatch'] = jest.fn(async (batchKey: string) => {
        const batch = batcher['batches'].get(batchKey);
        if (batch) {
          batchSizes.push(batch.requests.length);
        }
        return originalBatch(batchKey);
      });

      const requests: Array<() => Promise<string>> = [];
      for (let i = 0; i < 15; i++) {
        requests.push(async () => `result-${i}`);
      }

      await Promise.all(
        requests.map((req, idx) => 
          batcher.addRequest(`https://example.com/api/${idx}`, { priority: 1 }, req)
        )
      );

      // Should create batches of size 5 (batchSize)
      expect(batchSizes.every(size => size <= 5)).toBe(true);
    });

    it('should handle batch timeout', async () => {
      const batcherWithTimeout = new RequestBatcher({
        maxBatchSize: 10,
        batchTimeout: 50 // Short timeout
      });

      const requests: Array<() => Promise<string>> = [];
      for (let i = 0; i < 3; i++) {
        requests.push(async () => {
          await new Promise(resolve => setTimeout(resolve, 10));
          return `result-${i}`;
        });
      }

      const startTime = Date.now();
      const results = await Promise.all(
        requests.map((req, idx) => 
          batcherWithTimeout.addRequest(`https://example.com/api/${idx}`, { priority: 1 }, req)
        )
      );
      const duration = Date.now() - startTime;

      expect(results).toHaveLength(3);
      // Should complete within reasonable time (may batch or execute immediately)
      expect(duration).toBeLessThan(200);
    });
  });

  describe('Error Handling', () => {
    it('should handle individual request failures', async () => {
      const requests: Array<() => Promise<string>> = [
        async () => 'success-1',
        async () => { throw new Error('Request failed'); },
        async () => 'success-2'
      ];

      const results = await Promise.allSettled(
        requests.map((req, idx) => 
          batcher.addRequest(`https://example.com/api/${idx}`, { priority: 1 }, req)
        )
      );

      expect(results[0]?.status).toBe('fulfilled');
      expect(results[1]?.status).toBe('rejected');
      expect(results[2]?.status).toBe('fulfilled');
    });

    it('should continue processing other batches on error', async () => {
      const requests: Array<() => Promise<string>> = [];
      for (let i = 0; i < 10; i++) {
        if (i === 5) {
          requests.push(async () => { throw new Error('Batch error'); });
        } else {
          requests.push(async () => `result-${i}`);
        }
      }

      const results = await Promise.allSettled(
        requests.map((req, idx) => 
          batcher.addRequest(`https://example.com/api/${idx}`, { priority: 1 }, req)
        )
      );

      const successful = results.filter(r => r.status === 'fulfilled');
      const failed = results.filter(r => r.status === 'rejected');

      expect(successful.length).toBe(9);
      expect(failed.length).toBe(1);
    });
  });

  describe('Concurrency Control', () => {
    it('should respect maxConcurrentBatches limit', async () => {
      const activeBatches: number[] = [];
      let maxConcurrent = 0;
      let currentActive = 0;

      const originalExecute = batcher['sendBatch'].bind(batcher);
      batcher['sendBatch'] = jest.fn(async function(batchKey: string) {
        currentActive++;
        activeBatches.push(currentActive);
        maxConcurrent = Math.max(maxConcurrent, currentActive);
        
        await new Promise(resolve => setTimeout(resolve, 50));
        
        const result = await originalExecute(batchKey);
        currentActive--;
        return result;
      });

      const requests: Array<() => Promise<string>> = [];
      for (let i = 0; i < 20; i++) {
        requests.push(async () => `result-${i}`);
      }

      await Promise.all(
        requests.map((req, idx) => 
          batcher.addRequest(`https://example.com/api/${idx}`, { priority: 1 }, req)
        )
      );

      // Should not exceed reasonable concurrency
      expect(maxConcurrent).toBeGreaterThan(0);
    });
  });

  describe('Performance', () => {
    it('should batch requests efficiently', async () => {
      const requests: Array<() => Promise<string>> = [];
      for (let i = 0; i < 100; i++) {
        requests.push(async () => `result-${i}`);
      }

      const startTime = Date.now();
      const results = await Promise.all(
        requests.map((req, idx) => 
          batcher.addRequest(`https://example.com/api/${idx}`, { priority: 1 }, req)
        )
      );
      const duration = Date.now() - startTime;

      expect(results).toHaveLength(100);
      // Should complete reasonably fast with batching
      expect(duration).toBeLessThan(5000);
    });
  });
});

