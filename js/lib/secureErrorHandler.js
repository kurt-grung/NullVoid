/**
 * Comprehensive Error Handling and Input Validation for NullVoid
 * Provides secure error handling and input validation to prevent attacks
 */

const fs = require('fs');
const path = require('path');
const { VALIDATION_CONFIG } = require('./config');

/**
 * Custom error classes for different types of security issues
 */
class NullVoidError extends Error {
  constructor(message, code, details = {}) {
    super(message);
    this.name = 'NullVoidError';
    this.code = code;
    this.details = details;
    this.timestamp = new Date().toISOString();
  }
}

class SecurityError extends NullVoidError {
  constructor(message, code, details = {}) {
    super(message, code, details);
    this.name = 'SecurityError';
    this.severity = 'HIGH';
  }
}

class ValidationError extends NullVoidError {
  constructor(message, code, details = {}) {
    super(message, code, details);
    this.name = 'ValidationError';
    this.severity = 'MEDIUM';
  }
}

class PathTraversalError extends SecurityError {
  constructor(message, details = {}) {
    super(message, 'PATH_TRAVERSAL', details);
    this.name = 'PathTraversalError';
    this.severity = 'CRITICAL';
  }
}

class CommandInjectionError extends SecurityError {
  constructor(message, details = {}) {
    super(message, 'COMMAND_INJECTION', details);
    this.name = 'CommandInjectionError';
    this.severity = 'CRITICAL';
  }
}

class MaliciousCodeError extends SecurityError {
  constructor(message, details = {}) {
    super(message, 'MALICIOUS_CODE_DETECTED', details);
    this.name = 'MaliciousCodeError';
    this.severity = 'CRITICAL';
  }
}

/**
 * Input validation utilities
 */
class InputValidator {
  /**
   * Validate package name format and security
   * @param {string} packageName - Package name to validate
   * @returns {string} Validated package name
   * @throws {ValidationError} If package name is invalid
   */
  static validatePackageName(packageName) {
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
   * @param {string} filePath - File path to validate
   * @param {string} basePath - Base directory for validation
   * @returns {string} Validated file path
   * @throws {PathTraversalError} If path traversal is detected
   */
  static validateFilePath(filePath, basePath = process.cwd()) {
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
   * @param {object} options - Scan options to validate
   * @returns {object} Validated scan options
   * @throws {ValidationError} If options are invalid
   */
  static validateScanOptions(options) {
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
   * @param {string} content - File content to validate
   * @param {string} filename - Filename for context
   * @returns {boolean} True if content is safe
   * @throws {MaliciousCodeError} If malicious code is detected
   */
  static validateFileContent(content, filename = 'unknown') {
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
class ErrorHandler {
  constructor() {
    this.errorLog = [];
    this.setupGlobalHandlers();
  }
  
  /**
   * Setup global error handlers
   */
  setupGlobalHandlers() {
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
   * @param {Error} error - Error to handle
   * @param {string} type - Error type
   * @param {object} context - Additional context
   */
  handleError(error, type = 'UNKNOWN', context = {}) {
    const errorEntry = {
      timestamp: new Date().toISOString(),
      type,
      error: {
        name: error.name,
        message: error.message,
        code: error.code,
        stack: error.stack,
        details: error.details
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
    if (error instanceof SecurityError && error.severity === 'CRITICAL') {
      console.error('🚨 Critical security error detected. Exiting...');
      process.exit(1);
    }
  }
  
  /**
   * Log error to file for analysis
   * @param {object} errorEntry - Error entry to log
   */
  logErrorToFile(errorEntry) {
    try {
      const logFile = 'nullvoid-errors.log';
      const logEntry = JSON.stringify(errorEntry) + '\n';
      fs.appendFileSync(logFile, logEntry);
    } catch (error) {
      console.error('Failed to log error to file:', error.message);
    }
  }
  
  /**
   * Get error statistics
   * @returns {object} Error statistics
   */
  getErrorStats() {
    const stats = {
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
  clearErrorLog() {
    this.errorLog = [];
  }
}

// Create global error handler instance
const globalErrorHandler = new ErrorHandler();

/**
 * Safe execution wrapper with error handling
 * @param {Function} fn - Function to execute safely
 * @param {string} context - Context for error reporting
 * @param {object} options - Execution options
 * @returns {Promise<any>} Function result or error
 */
async function safeExecute(fn, context = 'unknown', options = {}) {
  try {
    return await fn();
  } catch (error) {
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
class RateLimitedLogger {
  constructor(maxErrorsPerMinute = 100) {
    this.maxErrorsPerMinute = maxErrorsPerMinute;
    this.errorCounts = new Map();
    this.lastReset = Date.now();
  }
  
  /**
   * Log error with rate limiting
   * @param {Error} error - Error to log
   * @param {string} context - Error context
   */
  logError(error, context = 'unknown') {
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
const rateLimitedLogger = new RateLimitedLogger();

module.exports = {
  NullVoidError,
  SecurityError,
  ValidationError,
  PathTraversalError,
  CommandInjectionError,
  MaliciousCodeError,
  InputValidator,
  ErrorHandler,
  globalErrorHandler,
  safeExecute,
  RateLimitedLogger,
  rateLimitedLogger
};
