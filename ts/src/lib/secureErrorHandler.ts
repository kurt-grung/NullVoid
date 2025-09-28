import { Threat, createThreat } from '../types/core';
import * as fs from 'fs';
import * as path from 'path';
import { VALIDATION_CONFIG } from './config';

/**
 * Custom error classes for different types of security issues
 */
export class NullVoidError extends Error {
  public code: string;
  public details: any;
  public timestamp: string;
  
  constructor(message: string, code: string, details: any = {}) {
    super(message);
    this.name = 'NullVoidError';
    this.code = code;
    this.details = details;
    this.timestamp = new Date().toISOString();
  }
}

export class SecurityError extends NullVoidError {
  public severity: string;
  
  constructor(message: string, code: string, details: any = {}) {
    super(message, code, details);
    this.name = 'SecurityError';
    this.severity = 'HIGH';
  }
}

export class ValidationError extends NullVoidError {
  public severity: string;
  
  constructor(message: string, code: string, details: any = {}) {
    super(message, code, details);
    this.name = 'ValidationError';
    this.severity = 'MEDIUM';
  }
}

export class PathTraversalError extends SecurityError {
  constructor(message: string, details: any = {}) {
    super(message, 'PATH_TRAVERSAL', details);
    this.name = 'PathTraversalError';
    this.severity = 'CRITICAL';
  }
}

export class CommandInjectionError extends SecurityError {
  constructor(message: string, details: any = {}) {
    super(message, 'COMMAND_INJECTION', details);
    this.name = 'CommandInjectionError';
    this.severity = 'CRITICAL';
  }
}

export class MaliciousCodeError extends SecurityError {
  constructor(message: string, details: any = {}) {
    super(message, 'MALICIOUS_CODE_DETECTED', details);
    this.name = 'MaliciousCodeError';
    this.severity = 'CRITICAL';
  }
}

export interface ErrorDetails {
  name: string;
  message: string;
  code?: string;
  stack?: string;
  details?: any;
}

export interface ErrorEntry {
  timestamp: string;
  type: string;
  error: ErrorDetails;
  context: any;
}

export interface ErrorStats {
  total: number;
  byType: Record<string, number>;
  bySeverity: Record<string, number>;
  recent: ErrorEntry[];
}

export interface ExecutionOptions {
  throwOnError?: boolean;
  timeout?: number;
  retries?: number;
}

/**
 * Input validation utilities
 */
export class InputValidator {
  /**
   * Validate package name format and security
   */
  static validatePackageName(packageName: string): string {
    if (!packageName || typeof packageName !== 'string') {
      throw new ValidationError('Package name must be a non-empty string', 'INVALID_INPUT');
    }
    
    // Check for command injection patterns
    for (const pattern of VALIDATION_CONFIG.DANGEROUS_PATTERNS) {
      if (pattern.test(packageName)) {
        throw new CommandInjectionError(
          'Potentially malicious input detected in package name',
          { packageName, pattern: pattern.toString() }
        );
      }
    }
    
    // Validate npm package name format OR local path
    if (!VALIDATION_CONFIG.VALID_PACKAGE_NAME.test(packageName) && !VALIDATION_CONFIG.VALID_LOCAL_PATH.test(packageName)) {
      throw new ValidationError(
        `Invalid package name format: ${packageName}`,
        'INVALID_PACKAGE_FORMAT',
        { packageName }
      );
    }
    
    // Check for suspicious patterns
    for (const pattern of VALIDATION_CONFIG.SUSPICIOUS_PATTERNS) {
      if (pattern.test(packageName)) {
        throw new SecurityError(
          `Suspicious package name pattern: ${packageName}`,
          'SUSPICIOUS_PACKAGE_NAME',
          { packageName, pattern: pattern.toString() }
        );
      }
    }
    
    return packageName.trim();
  }
  
  /**
   * Validate file path for security
   */
  static validateFilePath(filePath: string, basePath: string = process.cwd()): string {
    if (!filePath || typeof filePath !== 'string') {
      throw new ValidationError('File path must be a non-empty string', 'INVALID_INPUT');
    }
    
    // Check for path traversal patterns
    for (const pattern of VALIDATION_CONFIG.TRAVERSAL_PATTERNS) {
      if (pattern.test(filePath)) {
        throw new PathTraversalError(
          'Path traversal attempt detected',
          { filePath, pattern: pattern.toString() }
        );
      }
    }
    
    // Normalize and resolve path
    const normalizedPath = path.normalize(filePath);
    const absolutePath = path.resolve(basePath, normalizedPath);
    
    // Ensure path is within allowed boundaries
    const baseAbsolute = path.resolve(basePath);
    if (!absolutePath.startsWith(baseAbsolute)) {
      throw new PathTraversalError(
        'Path traversal attempt detected',
        { 
          inputPath: filePath,
          resolvedPath: absolutePath,
          basePath: baseAbsolute
        }
      );
    }
    
    return absolutePath;
  }
  
  /**
   * Validate scan options
   */
  static validateScanOptions(options: any): any {
    if (!options || typeof options !== 'object') {
      throw new ValidationError('Scan options must be an object', 'INVALID_INPUT');
    }
    
    const validatedOptions = { ...options };
    
    // Check for command injection in string values
    // Validate all string values for command injection
    for (const [key, value] of Object.entries(validatedOptions)) {
      if (typeof value === 'string') {
        for (const pattern of VALIDATION_CONFIG.DANGEROUS_PATTERNS) {
          if (pattern.test(value)) {
            throw new CommandInjectionError(
              `Potentially malicious input detected in option ${key}`,
              { option: key, value, pattern: pattern.toString() }
            );
          }
        }
      }
    }
    
    // Validate depth
    if (validatedOptions.depth !== undefined) {
      const depth = parseInt(validatedOptions.depth);
      if (isNaN(depth) || depth < 0 || depth > 10) {
        throw new ValidationError(
          'Scan depth must be a number between 0 and 10',
          'INVALID_DEPTH',
          { depth: validatedOptions.depth }
        );
      }
      validatedOptions.depth = depth;
    }
    
    // Validate workers
    if (validatedOptions.workers !== undefined) {
      if (validatedOptions.workers !== 'auto') {
        const workers = parseInt(validatedOptions.workers);
        if (isNaN(workers) || workers < 1 || workers > 16) {
          throw new ValidationError(
            'Number of workers must be between 1 and 16',
            'INVALID_WORKERS',
            { workers: validatedOptions.workers }
          );
        }
        validatedOptions.workers = workers;
      }
    }
    
    // Validate output format
    if (validatedOptions.output !== undefined) {
      if (!VALIDATION_CONFIG.VALID_OUTPUT_FORMATS.includes(validatedOptions.output)) {
        throw new ValidationError(
          `Output format must be one of: ${VALIDATION_CONFIG.VALID_OUTPUT_FORMATS.join(', ')}`,
          'INVALID_OUTPUT_FORMAT',
          { output: validatedOptions.output }
        );
      }
    }
    
    return validatedOptions;
  }
  
  /**
   * Validate file content for malicious patterns
   */
  static validateFileContent(content: string, filename: string = 'unknown'): boolean {
    if (!content || typeof content !== 'string') {
      throw new ValidationError('File content must be a non-empty string', 'INVALID_INPUT');
    }
    
    // Check for malicious patterns
    for (const pattern of VALIDATION_CONFIG.MALICIOUS_PATTERNS) {
      if (pattern.test(content)) {
        throw new MaliciousCodeError(
          'Potentially malicious code detected',
          { 
            filename, 
            pattern: pattern.toString(),
            match: content.match(pattern)?.[0]
          }
        );
      }
    }
    
    return true;
  }
}

/**
 * Global error handlers
 */
export class ErrorHandler {
  private errorLog: ErrorEntry[];
  
  constructor() {
    this.errorLog = [];
    this.setupGlobalHandlers();
  }
  
  /**
   * Setup global error handlers
   */
  private setupGlobalHandlers(): void {
    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      this.handleError(error, 'UNCAUGHT_EXCEPTION');
    });
    
    // Handle unhandled promise rejections
    process.on('unhandledRejection', (reason, promise) => {
      this.handleError(
        new Error(`Unhandled Promise Rejection: ${reason}`),
        'UNHANDLED_REJECTION',
        { reason, promise }
      );
    });
    
    // Handle warnings
    process.on('warning', (warning) => {
      this.handleError(
        new Error(`Process Warning: ${warning.message}`),
        'PROCESS_WARNING',
        { warning }
      );
    });
  }
  
  /**
   * Handle errors with appropriate logging and response
   */
  handleError(error: Error, type: string = 'UNKNOWN', context: any = {}): void {
    const errorEntry: ErrorEntry = {
      timestamp: new Date().toISOString(),
      type,
      error: {
        name: error.name,
        message: error.message,
        code: (error as any).code,
        stack: error.stack || '',
        details: (error as any).details
      },
      context
    };
    
    // Add to error log
    this.errorLog.push(errorEntry);
    
    // Log based on error severity
    if (error instanceof SecurityError) {
      console.error('🔴 SECURITY ERROR:', error.message);
      if (error.code === 'MALICIOUS_CODE_DETECTED') {
        console.error('⚠️  Malicious code attempted to execute!');
      }
    } else if (error instanceof ValidationError) {
      console.warn('🟡 VALIDATION ERROR:', error.message);
    } else {
      console.error('💀 CRITICAL ERROR:', error.message);
    }
    
    // Log to file for analysis
    this.logErrorToFile(errorEntry);
    
    // Exit on critical errors
    if (error instanceof SecurityError && (error as any).severity === 'CRITICAL') {
      console.error('🚨 Critical security error detected. Exiting...');
      process.exit(1);
    }
  }
  
  /**
   * Log error to file for analysis
   */
  private logErrorToFile(errorEntry: ErrorEntry): void {
    try {
      const logFile = 'nullvoid-errors.log';
      const logEntry = JSON.stringify(errorEntry) + '\n';
      fs.appendFileSync(logFile, logEntry);
    } catch (error: any) {
      console.error('Failed to log error to file:', error.message);
    }
  }
  
  /**
   * Get error statistics
   */
  getErrorStats(): ErrorStats {
    const stats: ErrorStats = {
      total: this.errorLog.length,
      byType: {},
      bySeverity: {},
      recent: this.errorLog.slice(-10)
    };
    
    for (const entry of this.errorLog) {
      // Count by type
      stats.byType[entry.type] = (stats.byType[entry.type] || 0) + 1;
      
      // Count by severity
      const severity = entry.error.details?.severity || 'UNKNOWN';
      stats.bySeverity[severity] = (stats.bySeverity[severity] || 0) + 1;
    }
    
    return stats;
  }
  
  /**
   * Clear error log
   */
  clearErrorLog(): void {
    this.errorLog = [];
  }
  
  /**
   * Handle error and return threats
   */
  handle(error: Error): Threat[] {
    const threats: Threat[] = [];
    
    // Convert error to threat based on type
    if (error instanceof SecurityError) {
      const severity = (error as any).severity === 'CRITICAL' ? 'CRITICAL' : 'HIGH';
      threats.push(createThreat(
        'SECURITY_ERROR',
        error.message,
        'unknown',
        'unknown',
        severity,
        error.stack || 'No stack trace available',
        { 
          errorType: error.name,
          timestamp: (error as any).timestamp,
          details: (error as any).details
        }
      ));
    } else if (error instanceof ValidationError) {
      threats.push(createThreat(
        'VALIDATION_ERROR',
        error.message,
        'unknown',
        'unknown',
        'MEDIUM',
        error.stack || 'No stack trace available',
        { 
          errorType: error.name,
          timestamp: (error as any).timestamp,
          details: (error as any).details
        }
      ));
    } else {
      threats.push(createThreat(
        'UNKNOWN_ERROR',
        error.message,
        'unknown',
        'unknown',
        'LOW',
        error.stack || 'No stack trace available',
        { 
          errorType: error.name,
          timestamp: new Date().toISOString()
        }
      ));
    }
    
    return threats;
  }
}

// Create global error handler instance
export const globalErrorHandler = new ErrorHandler();

/**
 * Safe execution wrapper with error handling
 */
export async function safeExecute<T>(fn: () => Promise<T>, context: string = 'unknown', options: ExecutionOptions = {}): Promise<T | null> {
  try {
    return await fn();
  } catch (error: any) {
    globalErrorHandler.handleError(error, 'SAFE_EXECUTION', { context, options });
    
    if (options.throwOnError !== false) {
      throw error;
    }
    
    return null;
  }
}

/**
 * Rate-limited error logging to prevent log flooding
 */
export class RateLimitedLogger {
  private maxErrorsPerMinute: number;
  private errorCounts: Map<string, number>;
  private lastReset: number;
  
  constructor(maxErrorsPerMinute: number = 100) {
    this.maxErrorsPerMinute = maxErrorsPerMinute;
    this.errorCounts = new Map();
    this.lastReset = Date.now();
  }
  
  /**
   * Log error with rate limiting
   */
  logError(error: Error, context: string = 'unknown'): void {
    const now = Date.now();
    const minute = Math.floor(now / 60000);
    
    // Reset counters every minute
    if (minute !== this.lastReset) {
      this.errorCounts.clear();
      this.lastReset = minute;
    }
    
    // Check rate limit
    const errorKey = `${context}:${error.name}`;
    const count = this.errorCounts.get(errorKey) || 0;
    
    if (count >= this.maxErrorsPerMinute) {
      console.warn(`Rate limit exceeded for ${errorKey}. Suppressing further errors.`);
      return;
    }
    
    // Log error
    this.errorCounts.set(errorKey, count + 1);
    globalErrorHandler.handleError(error, 'RATE_LIMITED_LOG', { context });
  }
}

// Create rate-limited logger instance
export const rateLimitedLogger = new RateLimitedLogger();