/**
 * Provider HTTP Client
 * Central HTTP client for IoC providers with optional connection pooling and request batching
 */

import type { RequestInit } from 'node-fetch';
import type { Agent } from 'http';
import { NETWORK_OPTIMIZATION_CONFIG } from '../config';
import { getConnectionPool } from '../network/connectionPool';
import { getRequestBatcher } from '../network/requestBatcher';
import { fetchWithTimeout as fetchWithTimeoutImpl } from './fetchWithTimeout';

export type ProviderFetchOptions = RequestInit & { timeout?: number };

/**
 * Build fetch options with connection pool agent when enabled
 */
function withConnectionPool(url: string, options: ProviderFetchOptions): ProviderFetchOptions {
  if (!NETWORK_OPTIMIZATION_CONFIG.CONNECTION_POOL.enabled) {
    return options;
  }
  const pool = getConnectionPool();
  const agent = pool.getAgent(url) as Agent;
  return {
    ...options,
    agent,
  } as ProviderFetchOptions;
}

/**
 * Execute a single fetch (used when batching is disabled or as batcher requestFn)
 */
async function executeFetch(
  url: string,
  options: ProviderFetchOptions
): Promise<Awaited<ReturnType<typeof fetchWithTimeoutImpl>>> {
  const merged = withConnectionPool(url, options);
  return fetchWithTimeoutImpl(url, merged);
}

/**
 * Provider HTTP fetch: uses connection pool and optional request batching.
 * Use this in IoC providers instead of calling fetchWithTimeout directly.
 */
export async function providerFetch(
  url: string,
  options: ProviderFetchOptions = {}
): Promise<Awaited<ReturnType<typeof fetchWithTimeoutImpl>>> {
  if (!NETWORK_OPTIMIZATION_CONFIG.REQUEST_BATCHING.enabled) {
    return executeFetch(url, options);
  }

  const batcher = getRequestBatcher();
  const batchOptions: { timeout?: number; priority: number } = { priority: 1 };
  if (options.timeout !== undefined) {
    batchOptions.timeout = options.timeout;
  }
  return batcher.addRequest(url, batchOptions, () => executeFetch(url, options));
}
