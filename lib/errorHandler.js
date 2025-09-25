/**
 * Standardized Error Handling for NullVoid
 * Provides consistent error handling patterns across the application
 */

const { logger, createLogger } = require('./logger');

const errorLogger = createLogger('ErrorHandler');

/**
 * Base error class for NullVoid
 */
class NullVoidError extends Error {
  constructor(message, code, details = {}) {
    super(message);
    this.name = 'NullVoidError';
    this.code = code;
    this.details = details;
    this.timestamp = new Date().toISOString();
    this.stack = this.stack;
  }

  /**
   * Convert error to JSON
   * @returns {object} Error as JSON object
   */
  toJSON() {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      details: this.details,
      timestamp: this.timestamp,
      stack: this.stack
    };
  }

  /**
   * Convert error to string
   * @returns {string} Error as string
   */
  toString() {
    return `${this.name} [${this.code}]: ${this.message}`;
  }
}

/**
 * Network-related errors
 */
class NetworkError extends NullVoidError {
  constructor(message, details = {}) {
    super(message, 'NETWORK_ERROR', details);
    this.name = 'NetworkError';
  }
}

/**
 * Validation errors
 */
class ValidationError extends NullVoidError {
  constructor(message, field, value, details = {}) {
    super(message, 'VALIDATION_ERROR', { field, value, ...details });
    this.name = 'ValidationError';
    this.field = field;
    this.value = value;
  }
}

/**
 * Cache-related errors
 */
class CacheError extends NullVoidError {
  constructor(message, details = {}) {
    super(message, 'CACHE_ERROR', details);
    this.name = 'CacheError';
  }
}

/**
 * File system errors
 */
class FileSystemError extends NullVoidError {
  constructor(message, filePath, details = {}) {
    super(message, 'FILE_SYSTEM_ERROR', { filePath, ...details });
    this.name = 'FileSystemError';
    this.filePath = filePath;
  }
}

/**
 * Worker/parallel processing errors
 */
class WorkerError extends NullVoidError {
  constructor(message, workerId, details = {}) {
    super(message, 'WORKER_ERROR', { workerId, ...details });
    this.name = 'WorkerError';
    this.workerId = workerId;
  }
}

/**
 * Rate limiting errors
 */
class RateLimitError extends NullVoidError {
  constructor(message, retryAfter, details = {}) {
    super(message, 'RATE_LIMIT_ERROR', { retryAfter, ...details });
    this.name = 'RateLimitError';
    this.retryAfter = retryAfter;
  }
}

/**
 * Timeout errors
 */
class TimeoutError extends NullVoidError {
  constructor(message, timeout, details = {}) {
    super(message, 'TIMEOUT_ERROR', { timeout, ...details });
    this.name = 'TimeoutError';
    this.timeout = timeout;
  }
}

/**
 * Configuration errors
 */
class ConfigurationError extends NullVoidError {
  constructor(message, configKey, details = {}) {
    super(message, 'CONFIGURATION_ERROR', { configKey, ...details });
    this.name = 'ConfigurationError';
    this.configKey = configKey;
  }
}

/**
 * Error handler class
 */
class ErrorHandler {
  constructor(options = {}) {
    this.logErrors = options.logErrors !== false;
    this.logLevel = options.logLevel || 'error';
    this.includeStack = options.includeStack !== false;
    this.maxRetries = options.maxRetries || 3;
    this.retryDelay = options.retryDelay || 1000;
  }

  /**
   * Handle and log an error
   * @param {Error} error - Error to handle
   * @param {object} context - Additional context
   */
  handle(error, context = {}) {
    if (this.logErrors) {
      this.logError(error, context);
    }
    
    return this.formatError(error, context);
  }

  /**
   * Log error with appropriate level
   * @param {Error} error - Error to log
   * @param {object} context - Additional context
   */
  logError(error, context = {}) {
    const logData = {
      error: error.message,
      code: error.code || 'UNKNOWN',
      stack: this.includeStack ? error.stack : undefined,
      ...context
    };

    if (error instanceof ValidationError) {
      errorLogger.warn('Validation error', logData);
    } else if (error instanceof NetworkError) {
      errorLogger.error('Network error', logData);
    } else if (error instanceof RateLimitError) {
      errorLogger.warn('Rate limit error', logData);
    } else if (error instanceof TimeoutError) {
      errorLogger.warn('Timeout error', logData);
    } else {
      errorLogger.error('Unexpected error', logData);
    }
  }

  /**
   * Format error for output
   * @param {Error} error - Error to format
   * @param {object} context - Additional context
   * @returns {object} Formatted error
   */
  formatError(error, context = {}) {
    return {
      name: error.name,
      message: error.message,
      code: error.code || 'UNKNOWN',
      timestamp: new Date().toISOString(),
      ...context
    };
  }

  /**
   * Retry operation with exponential backoff
   * @param {Function} operation - Operation to retry
   * @param {object} options - Retry options
   * @returns {Promise<*>} Operation result
   */
  async retry(operation, options = {}) {
    const maxRetries = options.maxRetries || this.maxRetries;
    const retryDelay = options.retryDelay || this.retryDelay;
    const backoffFactor = options.backoffFactor || 2;
    
    let lastError;
    
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        return await operation();
      } catch (error) {
        lastError = error;
        
        if (attempt === maxRetries) {
          break;
        }
        
        // Don't retry certain types of errors
        if (this.isNonRetryableError(error)) {
          break;
        }
        
        const delay = retryDelay * Math.pow(backoffFactor, attempt);
        errorLogger.warn(`Retry attempt ${attempt + 1}/${maxRetries} after ${delay}ms`, {
          error: error.message,
          attempt: attempt + 1
        });
        
        await new Promise(resolve => {
          const timer = setTimeout(resolve, delay);
          timer.unref(); // Don't keep process alive
        });
      }
    }
    
    throw lastError;
  }

  /**
   * Check if error should not be retried
   * @param {Error} error - Error to check
   * @returns {boolean} True if non-retryable
   */
  isNonRetryableError(error) {
    if (error instanceof ValidationError) return true;
    if (error instanceof ConfigurationError) return true;
    if (error instanceof FileSystemError && error.message.includes('permission denied')) return true;
    
    return false;
  }

  /**
   * Wrap async function with error handling
   * @param {Function} fn - Function to wrap
   * @param {object} options - Error handling options
   * @returns {Function} Wrapped function
   */
  wrap(fn, options = {}) {
    return async (...args) => {
      try {
        return await fn(...args);
      } catch (error) {
        return this.handle(error, { function: fn.name, args: args.length });
      }
    };
  }

  /**
   * Wrap sync function with error handling
   * @param {Function} fn - Function to wrap
   * @param {object} options - Error handling options
   * @returns {Function} Wrapped function
   */
  wrapSync(fn, options = {}) {
    return (...args) => {
      try {
        return fn(...args);
      } catch (error) {
        return this.handle(error, { function: fn.name, args: args.length });
      }
    };
  }
}

/**
 * Error recovery strategies
 */
class ErrorRecovery {
  /**
   * Recover from network errors
   * @param {NetworkError} error - Network error
   * @param {object} context - Recovery context
   * @returns {Promise<boolean>} True if recovered
   */
  static async recoverFromNetworkError(error, context = {}) {
    if (error.message.includes('timeout')) {
      // Increase timeout and retry
      context.timeout = (context.timeout || 5000) * 2;
      return true;
    }
    
    if (error.message.includes('ECONNRESET')) {
      // Wait and retry
      await new Promise(resolve => setTimeout(resolve, 2000));
      return true;
    }
    
    return false;
  }

  /**
   * Recover from rate limit errors
   * @param {RateLimitError} error - Rate limit error
   * @param {object} context - Recovery context
   * @returns {Promise<boolean>} True if recovered
   */
  static async recoverFromRateLimitError(error, context = {}) {
    const retryAfter = error.retryAfter || 60;
    errorLogger.info(`Rate limited, waiting ${retryAfter} seconds`);
    await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
    return true;
  }

  /**
   * Recover from cache errors
   * @param {CacheError} error - Cache error
   * @param {object} context - Recovery context
   * @returns {Promise<boolean>} True if recovered
   */
  static async recoverFromCacheError(error, context = {}) {
    // Clear cache and continue without caching
    if (context.cache) {
      context.cache.clear();
      context.cache = null;
    }
    return true;
  }

  /**
   * Recover from file system errors
   * @param {FileSystemError} error - File system error
   * @param {object} context - Recovery context
   * @returns {Promise<boolean>} True if recovered
   */
  static async recoverFromFileSystemError(error, context = {}) {
    if (error.message.includes('permission denied')) {
      // Try with different permissions or skip file
      return false;
    }
    
    if (error.message.includes('no such file')) {
      // Skip missing files
      return true;
    }
    
    return false;
  }
}

/**
 * Error metrics collector
 */
class ErrorMetrics {
  constructor() {
    this.errors = new Map();
    this.totalErrors = 0;
    this.startTime = Date.now();
  }

  /**
   * Record an error
   * @param {Error} error - Error to record
   * @param {object} context - Additional context
   */
  record(error, context = {}) {
    this.totalErrors++;
    
    const errorKey = error.name || 'UnknownError';
    const count = this.errors.get(errorKey) || 0;
    this.errors.set(errorKey, count + 1);
    
    errorLogger.debug('Error recorded', {
      error: errorKey,
      count: count + 1,
      total: this.totalErrors
    });
  }

  /**
   * Get error statistics
   * @returns {object} Error statistics
   */
  getStats() {
    const duration = Date.now() - this.startTime;
    const errorRate = this.totalErrors / (duration / 1000);
    
    return {
      totalErrors: this.totalErrors,
      errorRate: errorRate,
      duration: duration,
      errorsByType: Object.fromEntries(this.errors),
      mostCommonError: this.getMostCommonError()
    };
  }

  /**
   * Get most common error type
   * @returns {string} Most common error type
   */
  getMostCommonError() {
    let maxCount = 0;
    let mostCommon = 'None';
    
    for (const [errorType, count] of this.errors.entries()) {
      if (count > maxCount) {
        maxCount = count;
        mostCommon = errorType;
      }
    }
    
    return mostCommon;
  }

  /**
   * Reset metrics
   */
  reset() {
    this.errors.clear();
    this.totalErrors = 0;
    this.startTime = Date.now();
  }
}

// Global error handler instance
const globalErrorHandler = new ErrorHandler({
  logErrors: true,
  logLevel: 'error',
  includeStack: process.env.NODE_ENV !== 'production'
});

// Global error metrics
const globalErrorMetrics = new ErrorMetrics();

/**
 * Handle uncaught exceptions
 */
process.on('uncaughtException', (error) => {
  globalErrorHandler.handle(error, { type: 'uncaughtException' });
  globalErrorMetrics.record(error);
  
  // Exit process for uncaught exceptions
  process.exit(1);
});

/**
 * Handle unhandled promise rejections
 */
process.on('unhandledRejection', (reason, promise) => {
  const error = reason instanceof Error ? reason : new Error(String(reason));
  globalErrorHandler.handle(error, { type: 'unhandledRejection' });
  globalErrorMetrics.record(error);
});

module.exports = {
  NullVoidError,
  NetworkError,
  ValidationError,
  CacheError,
  FileSystemError,
  WorkerError,
  RateLimitError,
  TimeoutError,
  ConfigurationError,
  ErrorHandler,
  ErrorRecovery,
  ErrorMetrics,
  globalErrorHandler,
  globalErrorMetrics
};
