/**
 * Fetch with timeout helper
 * Wraps node-fetch with timeout support
 */

import fetch from 'node-fetch';

/**
 * Fetch with timeout
 */
export async function fetchWithTimeout(
  url: string,
  options: Parameters<typeof fetch>[1] & { timeout?: number } = {}
): Promise<ReturnType<typeof fetch>> {
  const { timeout, ...fetchOptions } = options;
  
  if (!timeout) {
    return fetch(url, fetchOptions);
  }
  
  // Create timeout promise with cleanup
  let timeoutId: ReturnType<typeof setTimeout> | null = null;
  const timeoutPromise = new Promise<never>((_, reject) => {
    timeoutId = setTimeout(() => {
      reject(new Error(`Request timeout after ${timeout}ms`));
    }, timeout);
    // Don't keep process alive
    if (timeoutId && typeof timeoutId.unref === 'function') {
      timeoutId.unref();
    }
  });
  
  try {
    // Race between fetch and timeout
    const response = await Promise.race([
      fetch(url, fetchOptions),
      timeoutPromise
    ]);
    // Clear timeout if fetch completed first
    if (timeoutId) {
      clearTimeout(timeoutId);
    }
    return response;
  } catch (error) {
    // Clear timeout on error
    if (timeoutId) {
      clearTimeout(timeoutId);
    }
    if ((error as Error).message.includes('timeout')) {
      throw error;
    }
    throw error;
  }
}

