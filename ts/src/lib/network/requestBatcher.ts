/**
 * Request Batching System
 * Batches multiple API requests for efficiency
 */

import type {
  RequestBatchingConfig,
  BatchedRequest,
  RequestBatch,
  NetworkRequestOptions,
} from '../../types/network-types';
import { NETWORK_OPTIMIZATION_CONFIG } from '../config';
import { logger } from '../logger';

/**
 * Request batcher implementation
 */
export class RequestBatcher {
  private config: RequestBatchingConfig;
  private batches: Map<string, RequestBatch> = new Map();
  private batchTimers: Map<string, ReturnType<typeof setTimeout>> = new Map();

  constructor(config?: Partial<RequestBatchingConfig>) {
    this.config = {
      ...NETWORK_OPTIMIZATION_CONFIG.REQUEST_BATCHING,
      ...config,
    };
  }

  /**
   * Add request to batch
   */
  async addRequest<T>(
    url: string,
    options: Partial<NetworkRequestOptions>,
    requestFn: () => Promise<T>
  ): Promise<T> {
    if (!this.config.enabled) {
      // If batching disabled, execute immediately
      return requestFn();
    }

    // Determine batch key based on domain and priority
    const batchKey = this.getBatchKey(url, options.priority || 1);

    // Create request entry
    const request: BatchedRequest<T> = {
      id: `${Date.now()}-${Math.random()}`,
      url,
      options,
      requestFn,
      resolve: () => {},
      reject: () => {},
      timestamp: Date.now(),
    };

    // Create promise for this request
    const promise = new Promise<T>((resolve, reject) => {
      request.resolve = resolve as (value: unknown) => void;
      request.reject = reject;
    });

    // Get or create batch
    let batch = this.batches.get(batchKey);
    if (!batch) {
      batch = {
        id: batchKey,
        requests: [],
        priority: options.priority || 0,
        createdAt: Date.now(),
      };
      this.batches.set(batchKey, batch);
    }

    // Add request to batch
    batch.requests.push(request);

    // Check if batch should be sent
    if (batch.requests.length >= this.config.maxBatchSize) {
      await this.sendBatch(batchKey);
    } else {
      // Schedule batch send after maxWaitTime
      this.scheduleBatchSend(batchKey);
    }

    return promise;
  }

  /**
   * Get batch key for URL and priority
   */
  private getBatchKey(url: string, priority: number = 0): string {
    try {
      const urlObj = new URL(url);
      return `${urlObj.origin}-${priority}`;
    } catch {
      return `unknown-${priority}`;
    }
  }

  /**
   * Schedule batch send
   */
  private scheduleBatchSend(batchKey: string): void {
    // Clear existing timer
    const existingTimer = this.batchTimers.get(batchKey);
    if (existingTimer) {
      clearTimeout(existingTimer);
    }

    // Schedule new timer
    const timer = setTimeout(() => {
      this.sendBatch(batchKey).catch((error) => {
        logger.error(`Error sending batch ${batchKey}:`, error);
      });
    }, this.config.maxWaitTime);

    this.batchTimers.set(batchKey, timer);

    // Don't keep process alive
    if (timer.unref) {
      timer.unref();
    }
  }

  /**
   * Send batch of requests
   */
  private async sendBatch(batchKey: string): Promise<void> {
    const batch = this.batches.get(batchKey);
    if (!batch || batch.requests.length === 0) {
      return;
    }

    // Clear timer
    const timer = this.batchTimers.get(batchKey);
    if (timer) {
      clearTimeout(timer);
      this.batchTimers.delete(batchKey);
    }

    // Remove batch from map
    this.batches.delete(batchKey);

    // Sort requests by priority (higher priority first)
    batch.requests.sort((a, b) => (b.options.priority || 0) - (a.options.priority || 0));

    // Execute requests in parallel (up to batch size limit)
    const requestsToProcess = batch.requests.slice(0, this.config.maxBatchSize);
    const remainingRequests = batch.requests.slice(this.config.maxBatchSize);

    // Process batch
    const promises = requestsToProcess.map(async (request) => {
      try {
        // Execute the provided request function
        const data = await request.requestFn();
        request.resolve(data);
      } catch (error) {
        request.reject(error instanceof Error ? error : new Error(String(error)));
      }
    });

    await Promise.allSettled(promises);

    // If there are remaining requests, create new batch
    if (remainingRequests.length > 0) {
      const newBatch: RequestBatch = {
        id: batchKey,
        requests: remainingRequests,
        priority: batch.priority,
        createdAt: Date.now(),
      };
      this.batches.set(batchKey, newBatch);
      this.scheduleBatchSend(batchKey);
    }
  }

  /**
   * Flush all pending batches
   */
  async flush(): Promise<void> {
    const batchKeys = Array.from(this.batches.keys());
    await Promise.all(batchKeys.map((key) => this.sendBatch(key)));
  }

  /**
   * Get batch statistics
   */
  getStats(): {
    activeBatches: number;
    totalPendingRequests: number;
    averageBatchSize: number;
  } {
    let totalRequests = 0;
    let batchCount = 0;

    for (const batch of this.batches.values()) {
      totalRequests += batch.requests.length;
      batchCount++;
    }

    return {
      activeBatches: batchCount,
      totalPendingRequests: totalRequests,
      averageBatchSize: batchCount > 0 ? totalRequests / batchCount : 0,
    };
  }

  /**
   * Clear all batches
   */
  clear(): void {
    // Clear all timers
    for (const timer of this.batchTimers.values()) {
      clearTimeout(timer);
    }
    this.batchTimers.clear();

    // Reject all pending requests
    for (const batch of this.batches.values()) {
      for (const request of batch.requests) {
        request.reject(new Error('Batch cleared'));
      }
    }

    this.batches.clear();
  }
}

/**
 * Global request batcher instance
 */
let globalRequestBatcher: RequestBatcher | null = null;

/**
 * Get or create global request batcher
 */
export function getRequestBatcher(config?: Partial<RequestBatchingConfig>): RequestBatcher {
  if (!globalRequestBatcher) {
    globalRequestBatcher = new RequestBatcher(config);
  }
  return globalRequestBatcher;
}
