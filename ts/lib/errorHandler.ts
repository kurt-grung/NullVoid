/**
 * Standardized Error Handling for NullVoid
 * Provides consistent error handling patterns across the application
 * Migrated from JavaScript to TypeScript with enhanced type safety
 */

import { createLogger, LogMetadata } from './logger';

const errorLogger = createLogger('ErrorHandler');

/**
 * Error details interface
 */
export interface ErrorDetails {
  [key: string]: unknown;
}

/**
 * Error context interface
 */
export interface ErrorContext {
  [key: string]: unknown;
}

/**
 * Retry options interface
 */
export interface RetryOptions {
  maxRetries?: number;
  retryDelay?: number;
  backoffFactor?: number;
}

/**
 * Error handler options interface
 */
export interface ErrorHandlerOptions {
  logErrors?: boolean;
  logLevel?: 'error' | 'warn' | 'info' | 'debug';
  includeStack?: boolean;
  maxRetries?: number;
  retryDelay?: number;
}

/**
 * Error statistics interface
 */
export interface ErrorStats {
  totalErrors: number;
  errorRate: number;
  duration: number;
  errorsByType: Record<string, number>;
  mostCommonError: string;
}

/**
 * Base error class for NullVoid
 */
export class NullVoidError extends Error {
  public readonly code: string;
  public readonly details: ErrorDetails;
  public readonly timestamp: string;

  constructor(message: string, code: string, details: ErrorDetails = {}) {
    super(message);
    this.name = 'NullVoidError';
    this.code = code;
    this.details = details;
    this.timestamp = new Date().toISOString();
    
    // Ensure proper prototype chain
    Object.setPrototypeOf(this, NullVoidError.prototype);
  }

  /**
   * Convert error to JSON
   * @returns Error as JSON object
   */
  toJSON(): Record<string, unknown> {
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
   * @returns Error as string
   */
  override toString(): string {
    return `${this.name} [${this.code}]: ${this.message}`;
  }
}

/**
 * Network-related errors
 */
export class NetworkError extends NullVoidError {
  constructor(message: string, details: ErrorDetails = {}) {
    super(message, 'NETWORK_ERROR', details);
    this.name = 'NetworkError';
    Object.setPrototypeOf(this, NetworkError.prototype);
  }
}

/**
 * Validation errors
 */
export class ValidationError extends NullVoidError {
  public readonly field: string;
  public readonly value: unknown;

  constructor(message: string, field: string, value: unknown, details: ErrorDetails = {}) {
    super(message, 'VALIDATION_ERROR', { field, value, ...details });
    this.name = 'ValidationError';
    this.field = field;
    this.value = value;
    Object.setPrototypeOf(this, ValidationError.prototype);
  }
}

/**
 * Cache-related errors
 */
export class CacheError extends NullVoidError {
  constructor(message: string, details: ErrorDetails = {}) {
    super(message, 'CACHE_ERROR', details);
    this.name = 'CacheError';
    Object.setPrototypeOf(this, CacheError.prototype);
  }
}

/**
 * File system errors
 */
export class FileSystemError extends NullVoidError {
  public readonly filePath: string;

  constructor(message: string, filePath: string, details: ErrorDetails = {}) {
    super(message, 'FILE_SYSTEM_ERROR', { filePath, ...details });
    this.name = 'FileSystemError';
    this.filePath = filePath;
    Object.setPrototypeOf(this, FileSystemError.prototype);
  }
}

/**
 * Worker/parallel processing errors
 */
export class WorkerError extends NullVoidError {
  public readonly workerId: string;

  constructor(message: string, workerId: string, details: ErrorDetails = {}) {
    super(message, 'WORKER_ERROR', { workerId, ...details });
    this.name = 'WorkerError';
    this.workerId = workerId;
    Object.setPrototypeOf(this, WorkerError.prototype);
  }
}

/**
 * Rate limiting errors
 */
export class RateLimitError extends NullVoidError {
  public readonly retryAfter: number;

  constructor(message: string, retryAfter: number, details: ErrorDetails = {}) {
    super(message, 'RATE_LIMIT_ERROR', { retryAfter, ...details });
    this.name = 'RateLimitError';
    this.retryAfter = retryAfter;
    Object.setPrototypeOf(this, RateLimitError.prototype);
  }
}

/**
 * Timeout errors
 */
export class TimeoutError extends NullVoidError {
  public readonly timeout: number;

  constructor(message: string, timeout: number, details: ErrorDetails = {}) {
    super(message, 'TIMEOUT_ERROR', { timeout, ...details });
    this.name = 'TimeoutError';
    this.timeout = timeout;
    Object.setPrototypeOf(this, TimeoutError.prototype);
  }
}

/**
 * Configuration errors
 */
export class ConfigurationError extends NullVoidError {
  public readonly configKey: string;

  constructor(message: string, configKey: string, details: ErrorDetails = {}) {
    super(message, 'CONFIGURATION_ERROR', { configKey, ...details });
    this.name = 'ConfigurationError';
    this.configKey = configKey;
    Object.setPrototypeOf(this, ConfigurationError.prototype);
  }
}

/**
 * Security errors
 */
export class SecurityError extends NullVoidError {
  constructor(message: string, details: ErrorDetails = {}) {
    super(message, 'SECURITY_ERROR', details);
    this.name = 'SecurityError';
    Object.setPrototypeOf(this, SecurityError.prototype);
  }
}

/**
 * Error handler class
 */
export class ErrorHandler {
  private logErrors: boolean;
  private includeStack: boolean;
  private maxRetries: number;
  private retryDelay: number;

  constructor(options: ErrorHandlerOptions = {}) {
    this.logErrors = options.logErrors !== false;
    this.includeStack = options.includeStack !== false;
    this.maxRetries = options.maxRetries || 3;
    this.retryDelay = options.retryDelay || 1000;
  }

  /**
   * Handle and log an error
   * @param error - Error to handle
   * @param context - Additional context
   * @returns Formatted error
   */
  handle(error: Error, context: ErrorContext = {}): Record<string, unknown> {
    if (this.logErrors) {
      this.logError(error, context);
    }
    
    return this.formatError(error, context);
  }

  /**
   * Log error with appropriate level
   * @param error - Error to log
   * @param context - Additional context
   */
  private logError(error: Error, context: ErrorContext = {}): void {
    const logData: LogMetadata = {
      error: error.message,
      code: (error as any).code || 'UNKNOWN',
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
    } else if (error instanceof SecurityError) {
      errorLogger.error('Security error', logData);
    } else {
      errorLogger.error('Unexpected error', logData);
    }
  }

  /**
   * Format error for output
   * @param error - Error to format
   * @param context - Additional context
   * @returns Formatted error
   */
  private formatError(error: Error, context: ErrorContext = {}): Record<string, unknown> {
    return {
      name: error.name,
      message: error.message,
      code: (error as any).code || 'UNKNOWN',
      timestamp: new Date().toISOString(),
      ...context
    };
  }

  /**
   * Retry operation with exponential backoff
   * @param operation - Operation to retry
   * @param options - Retry options
   * @returns Operation result
   */
  async retry<T>(
    operation: () => Promise<T>, 
    options: RetryOptions = {}
  ): Promise<T> {
    const maxRetries = options.maxRetries || this.maxRetries;
    const retryDelay = options.retryDelay || this.retryDelay;
    const backoffFactor = options.backoffFactor || 2;
    
    let lastError: Error;
    
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        return await operation();
      } catch (error) {
        lastError = error as Error;
        
        if (attempt === maxRetries) {
          break;
        }
        
        // Don't retry certain types of errors
        if (this.isNonRetryableError(error as Error)) {
          break;
        }
        
        const delay = retryDelay * Math.pow(backoffFactor, attempt);
        errorLogger.warn(`Retry attempt ${attempt + 1}/${maxRetries} after ${delay}ms`, {
          error: (error as Error).message,
          attempt: attempt + 1
        });
        
        await new Promise<void>(resolve => {
          const timer = setTimeout(() => resolve(), delay);
          timer.unref(); // Don't keep process alive
        });
      }
    }
    
    throw lastError!;
  }

  /**
   * Check if error should not be retried
   * @param error - Error to check
   * @returns True if non-retryable
   */
  private isNonRetryableError(error: Error): boolean {
    if (error instanceof ValidationError) return true;
    if (error instanceof ConfigurationError) return true;
    if (error instanceof SecurityError) return true;
    if (error instanceof FileSystemError && error.message.includes('permission denied')) return true;
    
    return false;
  }

  /**
   * Wrap async function with error handling
   * @param fn - Function to wrap
   * @param options - Error handling options
   * @returns Wrapped function
   */
  wrap<T extends any[], R>(
    fn: (...args: T) => Promise<R>
  ): (...args: T) => Promise<R | Record<string, unknown>> {
    return async (...args: T) => {
      try {
        return await fn(...args);
      } catch (error) {
        return this.handle(error as Error, { 
          function: fn.name, 
          args: args.length 
        });
      }
    };
  }

  /**
   * Wrap sync function with error handling
   * @param fn - Function to wrap
   * @returns Wrapped function
   */
  wrapSync<T extends any[], R>(
    fn: (...args: T) => R
  ): (...args: T) => R | Record<string, unknown> {
    return (...args: T) => {
      try {
        return fn(...args);
      } catch (error) {
        return this.handle(error as Error, { 
          function: fn.name, 
          args: args.length 
        });
      }
    };
  }
}

/**
 * Error recovery strategies
 */
export class ErrorRecovery {
  /**
   * Recover from network errors
   * @param error - Network error
   * @returns True if recovered
   */
  static async recoverFromNetworkError(error: NetworkError): Promise<boolean> {
    if (error.message.includes('timeout')) {
      // Increase timeout and retry
      return true;
    }
    
    if (error.message.includes('ECONNRESET')) {
      // Wait and retry
      await new Promise<void>(resolve => setTimeout(() => resolve(), 2000));
      return true;
    }
    
    return false;
  }

  /**
   * Recover from rate limit errors
   * @param error - Rate limit error
   * @returns True if recovered
   */
  static async recoverFromRateLimitError(error: RateLimitError): Promise<boolean> {
    const retryAfter = error.retryAfter || 60;
    errorLogger.info(`Rate limited, waiting ${retryAfter} seconds`);
    await new Promise<void>(resolve => setTimeout(() => resolve(), retryAfter * 1000));
    return true;
  }

  /**
   * Recover from cache errors
   * @param error - Cache error
   * @returns True if recovered
   */
  static async recoverFromCacheError(_error: CacheError): Promise<boolean> {
    // Clear cache and continue without caching
    return true;
  }

  /**
   * Recover from file system errors
   * @param error - File system error
   * @returns True if recovered
   */
  static async recoverFromFileSystemError(error: FileSystemError): Promise<boolean> {
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
export class ErrorMetrics {
  private errors: Map<string, number>;
  private totalErrors: number;
  private startTime: number;

  constructor() {
    this.errors = new Map();
    this.totalErrors = 0;
    this.startTime = Date.now();
  }

  /**
   * Record an error
   * @param error - Error to record
   */
  record(error: Error): void {
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
   * @returns Error statistics
   */
  getStats(): ErrorStats {
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
   * @returns Most common error type
   */
  private getMostCommonError(): string {
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
  reset(): void {
    this.errors.clear();
    this.totalErrors = 0;
    this.startTime = Date.now();
  }
}

// Global error handler instance
export const globalErrorHandler = new ErrorHandler({
  logErrors: true,
  logLevel: 'error',
  includeStack: process.env['NODE_ENV'] !== 'production'
});

// Global error metrics
export const globalErrorMetrics = new ErrorMetrics();

/**
 * Handle uncaught exceptions
 */
process.on('uncaughtException', (error: Error) => {
  globalErrorHandler.handle(error, { type: 'uncaughtException' });
  globalErrorMetrics.record(error);
  
  // Exit process for uncaught exceptions
  process.exit(1);
});

/**
 * Handle unhandled promise rejections
 */
process.on('unhandledRejection', (reason: unknown) => {
  const error = reason instanceof Error ? reason : new Error(String(reason));
  globalErrorHandler.handle(error, { type: 'unhandledRejection' });
  globalErrorMetrics.record(error);
});
