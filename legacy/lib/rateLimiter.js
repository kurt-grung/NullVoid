/**
 * Rate Limiting Implementation for NullVoid
 * Provides rate limiting for npm registry requests and other API calls
 */

const { NETWORK_CONFIG } = require('./config');
const { logger } = require('./logger');

/**
 * Rate limiter class
 */
class RateLimiter {
  constructor(options = {}) {
    this.maxRequests = options.maxRequests || NETWORK_CONFIG.RATE_LIMIT.MAX_REQUESTS;
    this.windowSize = options.windowSize || NETWORK_CONFIG.RATE_LIMIT.WINDOW_SIZE;
    this.requests = [];
    this.blockedUntil = 0;
  }

  /**
   * Check if request is allowed
   * @param {string} identifier - Request identifier (optional)
   * @returns {boolean} True if request is allowed
   */
  isAllowed(identifier = 'default') {
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
   * @param {string} identifier - Request identifier
   * @returns {Promise<void>} Promise that resolves when rate limit resets
   */
  async waitForReset(identifier = 'default') {
    const now = Date.now();
    const waitTime = this.blockedUntil - now;
    
    if (waitTime > 0) {
      logger.info(`Waiting ${waitTime}ms for rate limit to reset`, { identifier });
      await new Promise(resolve => {
        const timer = setTimeout(resolve, waitTime);
        timer.unref(); // Don't keep process alive
      });
    }
  }

  /**
   * Get current rate limit status
   * @returns {object} Rate limit status
   */
  getStatus() {
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
  reset() {
    this.requests = [];
    this.blockedUntil = 0;
  }
}

/**
 * Multi-identifier rate limiter
 */
class MultiRateLimiter {
  constructor(options = {}) {
    this.maxRequests = options.maxRequests || NETWORK_CONFIG.RATE_LIMIT.MAX_REQUESTS;
    this.windowSize = options.windowSize || NETWORK_CONFIG.RATE_LIMIT.WINDOW_SIZE;
    this.limiters = new Map();
  }

  /**
   * Get rate limiter for specific identifier
   * @param {string} identifier - Request identifier
   * @returns {RateLimiter} Rate limiter instance
   */
  getLimiter(identifier) {
    if (!this.limiters.has(identifier)) {
      this.limiters.set(identifier, new RateLimiter({
        maxRequests: this.maxRequests,
        windowSize: this.windowSize
      }));
    }
    return this.limiters.get(identifier);
  }

  /**
   * Check if request is allowed for identifier
   * @param {string} identifier - Request identifier
   * @returns {boolean} True if request is allowed
   */
  isAllowed(identifier) {
    return this.getLimiter(identifier).isAllowed(identifier);
  }

  /**
   * Wait for rate limit to reset for identifier
   * @param {string} identifier - Request identifier
   * @returns {Promise<void>} Promise that resolves when rate limit resets
   */
  async waitForReset(identifier) {
    return this.getLimiter(identifier).waitForReset(identifier);
  }

  /**
   * Get rate limit status for identifier
   * @param {string} identifier - Request identifier
   * @returns {object} Rate limit status
   */
  getStatus(identifier) {
    return this.getLimiter(identifier).getStatus();
  }

  /**
   * Get all rate limit statuses
   * @returns {object} All rate limit statuses
   */
  getAllStatuses() {
    const statuses = {};
    for (const [identifier, limiter] of this.limiters.entries()) {
      statuses[identifier] = limiter.getStatus();
    }
    return statuses;
  }

  /**
   * Reset rate limiter for identifier
   * @param {string} identifier - Request identifier
   */
  reset(identifier) {
    if (this.limiters.has(identifier)) {
      this.limiters.get(identifier).reset();
    }
  }

  /**
   * Reset all rate limiters
   */
  resetAll() {
    for (const limiter of this.limiters.values()) {
      limiter.reset();
    }
  }
}

/**
 * Request throttler with exponential backoff
 */
class RequestThrottler {
  constructor(options = {}) {
    this.baseDelay = options.baseDelay || 1000; // 1 second
    this.maxDelay = options.maxDelay || 30000; // 30 seconds
    this.backoffFactor = options.backoffFactor || 2;
    this.maxRetries = options.maxRetries || 5;
    this.retryCount = 0;
  }

  /**
   * Execute request with throttling
   * @param {Function} requestFn - Request function to execute
   * @param {string} identifier - Request identifier
   * @returns {Promise<*>} Request result
   */
  async execute(requestFn, identifier = 'default') {
    try {
      const result = await requestFn();
      this.retryCount = 0; // Reset on success
      return result;
    } catch (error) {
      if (this.retryCount >= this.maxRetries) {
        logger.error(`Max retries exceeded for ${identifier}`, { error: error.message });
        throw error;
      }

      const delay = Math.min(
        this.baseDelay * Math.pow(this.backoffFactor, this.retryCount),
        this.maxDelay
      );

      logger.warn(`Request failed for ${identifier}, retrying in ${delay}ms`, {
        error: error.message,
        retryCount: this.retryCount + 1,
        maxRetries: this.maxRetries
      });

      this.retryCount++;
      await new Promise(resolve => setTimeout(resolve, delay));
      return this.execute(requestFn, identifier);
    }
  }

  /**
   * Reset retry count
   */
  reset() {
    this.retryCount = 0;
  }
}

/**
 * Global rate limiter instances
 */
const npmRegistryLimiter = new MultiRateLimiter({
  maxRequests: NETWORK_CONFIG.RATE_LIMIT.MAX_REQUESTS,
  windowSize: NETWORK_CONFIG.RATE_LIMIT.WINDOW_SIZE
});

const requestThrottler = new RequestThrottler({
  baseDelay: 1000,
  maxDelay: 30000,
  backoffFactor: 2,
  maxRetries: 3
});

/**
 * Rate-limited request wrapper
 * @param {Function} requestFn - Request function
 * @param {string} identifier - Request identifier
 * @param {object} options - Options
 * @returns {Promise<*>} Request result
 */
async function rateLimitedRequest(requestFn, identifier = 'default', options = {}) {
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
 * @returns {object} Rate limit status
 */
function getNpmRegistryStatus() {
  return npmRegistryLimiter.getStatus('npm-registry');
}

/**
 * Reset npm registry rate limiter
 */
function resetNpmRegistryLimiter() {
  npmRegistryLimiter.reset('npm-registry');
}

module.exports = {
  RateLimiter,
  MultiRateLimiter,
  RequestThrottler,
  rateLimitedRequest,
  getNpmRegistryStatus,
  resetNpmRegistryLimiter,
  npmRegistryLimiter,
  requestThrottler
};
