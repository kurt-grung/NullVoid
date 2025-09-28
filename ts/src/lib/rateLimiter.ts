/**
 * Rate Limiting Implementation for NullVoid
 * Provides rate limiting for npm registry requests and other API calls
 * Migrated from JavaScript to TypeScript with enhanced type safety
 */

import { NETWORK_CONFIG } from './config';
import { logger } from './logger';

/**
 * Rate limit options interface
 */
export interface RateLimitOptions {
  maxRequests?: number;
  windowSize?: number;
}

/**
 * Rate limit status interface
 */
export interface RateLimitStatus {
  requests: number;
  maxRequests: number;
  windowSize: number;
  blockedUntil: number;
  isBlocked: boolean;
  remainingRequests: number;
}

/**
 * Request throttler options interface
 */
export interface ThrottlerOptions {
  baseDelay?: number;
  maxDelay?: number;
  backoffFactor?: number;
  maxRetries?: number;
}

/**
 * Rate limiter class
 */
export class RateLimiter {
  private maxRequests: number;
  private windowSize: number;
  private requests: number[];
  private blockedUntil: number;

  constructor(options: RateLimitOptions = {}) {
    this.maxRequests = options.maxRequests || NETWORK_CONFIG.RATE_LIMIT.MAX_REQUESTS;
    this.windowSize = options.windowSize || NETWORK_CONFIG.RATE_LIMIT.WINDOW_SIZE;
    this.requests = [];
    this.blockedUntil = 0;
  }

  /**
   * Check if request is allowed
   * @param identifier - Request identifier (optional)
   * @returns True if request is allowed
   */
  isAllowed(identifier: string = 'default'): boolean {
    const now = Date.now();
    
    // Check if we're still blocked
    if (now < this.blockedUntil) {
      return false;
    }
    
    // Clean old requests outside the window
    this.requests = this.requests.filter(timestamp => now - timestamp < this.windowSize);
    
    // Check if we've exceeded the limit
    if (this.requests.length >= this.maxRequests) {
      this.blockedUntil = now + this.windowSize;
      logger.warn(`Rate limit exceeded. Blocked until ${new Date(this.blockedUntil).toISOString()}`, {
        identifier,
        requests: this.requests.length,
        maxRequests: this.maxRequests
      });
      return false;
    }
    
    // Add current request
    this.requests.push(now);
    return true;
  }

  /**
   * Wait for rate limit to reset
   * @param identifier - Request identifier
   * @returns Promise that resolves when rate limit resets
   */
  async waitForReset(identifier: string = 'default'): Promise<void> {
    const now = Date.now();
    const waitTime = this.blockedUntil - now;
    
    if (waitTime > 0) {
      logger.info(`Waiting ${waitTime}ms for rate limit to reset`, { identifier });
      await new Promise<void>(resolve => {
        const timer = setTimeout(() => resolve(), waitTime);
        timer.unref(); // Don't keep process alive
      });
    }
  }

  /**
   * Get current rate limit status
   * @returns Rate limit status
   */
  getStatus(): RateLimitStatus {
    const now = Date.now();
    const activeRequests = this.requests.filter(timestamp => now - timestamp < this.windowSize);
    
    return {
      requests: activeRequests.length,
      maxRequests: this.maxRequests,
      windowSize: this.windowSize,
      blockedUntil: this.blockedUntil,
      isBlocked: now < this.blockedUntil,
      remainingRequests: Math.max(0, this.maxRequests - activeRequests.length)
    };
  }

  /**
   * Reset rate limiter
   */
  reset(): void {
    this.requests = [];
    this.blockedUntil = 0;
  }

  /**
   * Get remaining time until reset
   * @returns Time in milliseconds until reset
   */
  getTimeUntilReset(): number {
    const now = Date.now();
    return Math.max(0, this.blockedUntil - now);
  }

  /**
   * Check if rate limiter is currently blocked
   * @returns True if blocked
   */
  isBlocked(): boolean {
    return Date.now() < this.blockedUntil;
  }
}

/**
 * Multi-identifier rate limiter
 */
export class MultiRateLimiter {
  private maxRequests: number;
  private windowSize: number;
  private limiters: Map<string, RateLimiter>;

  constructor(options: RateLimitOptions = {}) {
    this.maxRequests = options.maxRequests || NETWORK_CONFIG.RATE_LIMIT.MAX_REQUESTS;
    this.windowSize = options.windowSize || NETWORK_CONFIG.RATE_LIMIT.WINDOW_SIZE;
    this.limiters = new Map();
  }

  /**
   * Get rate limiter for specific identifier
   * @param identifier - Request identifier
   * @returns Rate limiter instance
   */
  getLimiter(identifier: string): RateLimiter {
    if (!this.limiters.has(identifier)) {
      this.limiters.set(identifier, new RateLimiter({
        maxRequests: this.maxRequests,
        windowSize: this.windowSize
      }));
    }
    return this.limiters.get(identifier)!;
  }

  /**
   * Check if request is allowed for identifier
   * @param identifier - Request identifier
   * @returns True if request is allowed
   */
  isAllowed(identifier: string): boolean {
    return this.getLimiter(identifier).isAllowed(identifier);
  }

  /**
   * Wait for rate limit to reset for identifier
   * @param identifier - Request identifier
   * @returns Promise that resolves when rate limit resets
   */
  async waitForReset(identifier: string): Promise<void> {
    return this.getLimiter(identifier).waitForReset(identifier);
  }

  /**
   * Get rate limit status for identifier
   * @param identifier - Request identifier
   * @returns Rate limit status
   */
  getStatus(identifier: string): RateLimitStatus {
    return this.getLimiter(identifier).getStatus();
  }

  /**
   * Get all rate limit statuses
   * @returns All rate limit statuses
   */
  getAllStatuses(): Record<string, RateLimitStatus> {
    const statuses: Record<string, RateLimitStatus> = {};
    for (const [identifier, limiter] of this.limiters.entries()) {
      statuses[identifier] = limiter.getStatus();
    }
    return statuses;
  }

  /**
   * Reset rate limiter for identifier
   * @param identifier - Request identifier
   */
  reset(identifier: string): void {
    if (this.limiters.has(identifier)) {
      this.limiters.get(identifier)!.reset();
    }
  }

  /**
   * Reset all rate limiters
   */
  resetAll(): void {
    for (const limiter of this.limiters.values()) {
      limiter.reset();
    }
  }

  /**
   * Get all identifiers
   * @returns Array of identifiers
   */
  getIdentifiers(): string[] {
    return Array.from(this.limiters.keys());
  }

  /**
   * Remove rate limiter for identifier
   * @param identifier - Request identifier
   */
  remove(identifier: string): void {
    this.limiters.delete(identifier);
  }

  /**
   * Clear all rate limiters
   */
  clear(): void {
    this.limiters.clear();
  }
}

/**
 * Request throttler with exponential backoff
 */
export class RequestThrottler {
  private baseDelay: number;
  private maxDelay: number;
  private backoffFactor: number;
  private maxRetries: number;
  private retryCount: number;

  constructor(options: ThrottlerOptions = {}) {
    this.baseDelay = options.baseDelay || 1000; // 1 second
    this.maxDelay = options.maxDelay || 30000; // 30 seconds
    this.backoffFactor = options.backoffFactor || 2;
    this.maxRetries = options.maxRetries || 5;
    this.retryCount = 0;
  }

  /**
   * Execute request with throttling
   * @param requestFn - Request function to execute
   * @param identifier - Request identifier
   * @returns Request result
   */
  async execute<T>(requestFn: () => Promise<T>, identifier: string = 'default'): Promise<T> {
    try {
      const result = await requestFn();
      this.retryCount = 0; // Reset on success
      return result;
    } catch (error) {
      if (this.retryCount >= this.maxRetries) {
        logger.error(`Max retries exceeded for ${identifier}`, { 
          error: (error as Error).message,
          retryCount: this.retryCount,
          maxRetries: this.maxRetries
        });
        throw error;
      }

      const delay = Math.min(
        this.baseDelay * Math.pow(this.backoffFactor, this.retryCount),
        this.maxDelay
      );

      logger.warn(`Request failed for ${identifier}, retrying in ${delay}ms`, {
        error: (error as Error).message,
        retryCount: this.retryCount + 1,
        maxRetries: this.maxRetries,
        delay
      });

      this.retryCount++;
      await new Promise<void>(resolve => {
        const timer = setTimeout(() => resolve(), delay);
        timer.unref(); // Don't keep process alive
      });
      
      return this.execute(requestFn, identifier);
    }
  }

  /**
   * Reset retry count
   */
  reset(): void {
    this.retryCount = 0;
  }

  /**
   * Get current retry count
   * @returns Current retry count
   */
  getRetryCount(): number {
    return this.retryCount;
  }

  /**
   * Get remaining retries
   * @returns Remaining retries
   */
  getRemainingRetries(): number {
    return Math.max(0, this.maxRetries - this.retryCount);
  }
}

/**
 * Rate-limited request options interface
 */
export interface RateLimitedRequestOptions {
  limiter?: MultiRateLimiter;
  identifier?: string;
  timeout?: number;
}

/**
 * Global rate limiter instances
 */
export const npmRegistryLimiter = new MultiRateLimiter({
  maxRequests: NETWORK_CONFIG.RATE_LIMIT.MAX_REQUESTS,
  windowSize: NETWORK_CONFIG.RATE_LIMIT.WINDOW_SIZE
});

export const requestThrottler = new RequestThrottler({
  baseDelay: 1000,
  maxDelay: 30000,
  backoffFactor: 2,
  maxRetries: 3
});

/**
 * Rate-limited request wrapper
 * @param requestFn - Request function
 * @param identifier - Request identifier
 * @param options - Options
 * @returns Request result
 */
export async function rateLimitedRequest<T>(
  requestFn: () => Promise<T>, 
  identifier: string = 'default', 
  options: RateLimitedRequestOptions = {}
): Promise<T> {
  const limiter = options.limiter || npmRegistryLimiter;
  
  // Check if request is allowed
  if (!limiter.isAllowed(identifier)) {
    logger.warn(`Rate limit exceeded for ${identifier}, waiting for reset`);
    await limiter.waitForReset(identifier);
  }
  
  // Execute request with throttling
  return requestThrottler.execute(requestFn, identifier);
}

/**
 * Get rate limit status for npm registry
 * @returns Rate limit status
 */
export function getNpmRegistryStatus(): RateLimitStatus {
  return npmRegistryLimiter.getStatus('npm-registry');
}

/**
 * Reset npm registry rate limiter
 */
export function resetNpmRegistryLimiter(): void {
  npmRegistryLimiter.reset('npm-registry');
}

/**
 * Create a new rate limiter instance
 * @param options - Rate limiter options
 * @returns New rate limiter instance
 */
export function createRateLimiter(options: RateLimitOptions = {}): RateLimiter {
  return new RateLimiter(options);
}

/**
 * Create a new multi-rate limiter instance
 * @param options - Rate limiter options
 * @returns New multi-rate limiter instance
 */
export function createMultiRateLimiter(options: RateLimitOptions = {}): MultiRateLimiter {
  return new MultiRateLimiter(options);
}

/**
 * Create a new request throttler instance
 * @param options - Throttler options
 * @returns New request throttler instance
 */
export function createRequestThrottler(options: ThrottlerOptions = {}): RequestThrottler {
  return new RequestThrottler(options);
}

/**
 * Check if a request should be throttled based on error
 * @param error - Error to check
 * @returns True if request should be throttled
 */
export function shouldThrottleRequest(error: Error): boolean {
  const throttlableErrors = [
    'ECONNRESET',
    'ETIMEDOUT',
    'ENOTFOUND',
    'ECONNREFUSED',
    'rate limit',
    'too many requests',
    '429'
  ];
  
  return throttlableErrors.some(pattern => 
    error.message.toLowerCase().includes(pattern.toLowerCase())
  );
}

/**
 * Get optimal delay for retry based on error type
 * @param error - Error to analyze
 * @param attempt - Current attempt number
 * @returns Delay in milliseconds
 */
export function getRetryDelay(error: Error, attempt: number): number {
  const baseDelay = 1000;
  const maxDelay = 30000;
  const backoffFactor = 2;
  
  // Increase delay for rate limit errors
  if (error.message.includes('rate limit') || error.message.includes('429')) {
    return Math.min(baseDelay * Math.pow(backoffFactor * 2, attempt), maxDelay);
  }
  
  // Standard exponential backoff
  return Math.min(baseDelay * Math.pow(backoffFactor, attempt), maxDelay);
}
