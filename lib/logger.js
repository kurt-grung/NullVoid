/**
 * Centralized Logging System for NullVoid
 * Provides structured logging with different levels and output formatting
 */

const colors = require('../colors');

/**
 * Log levels in order of severity
 */
const LOG_LEVELS = {
  ERROR: 0,
  WARN: 1,
  INFO: 2,
  DEBUG: 3,
  VERBOSE: 4
};

/**
 * Logger class for structured logging
 */
class Logger {
  constructor(options = {}) {
    this.level = options.level || (process.env.NODE_ENV === 'test' ? LOG_LEVELS.ERROR : LOG_LEVELS.INFO);
    this.enableColors = options.enableColors !== false;
    this.prefix = options.prefix || 'NullVoid';
    this.timestamp = options.timestamp !== false;
  }

  /**
   * Set the logging level
   * @param {string|number} level - Log level name or number
   */
  setLevel(level) {
    if (typeof level === 'string') {
      this.level = LOG_LEVELS[level.toUpperCase()] || LOG_LEVELS.INFO;
    } else {
      this.level = level;
    }
  }

  /**
   * Format log message with timestamp and prefix
   * @param {string} level - Log level
   * @param {string} message - Log message
   * @param {object} meta - Additional metadata
   * @returns {string} Formatted log message
   */
  formatMessage(level, message, meta = {}) {
    const parts = [];
    
    if (this.timestamp) {
      parts.push(`[${new Date().toISOString()}]`);
    }
    
    parts.push(`[${this.prefix}]`);
    parts.push(`[${level}]`);
    parts.push(message);
    
    if (Object.keys(meta).length > 0) {
      parts.push(JSON.stringify(meta));
    }
    
    return parts.join(' ');
  }

  /**
   * Log error message
   * @param {string} message - Error message
   * @param {object} meta - Additional metadata
   */
  error(message, meta = {}) {
    if (this.level >= LOG_LEVELS.ERROR) {
      const formatted = this.formatMessage('ERROR', message, meta);
      console.error(this.enableColors ? colors.red(formatted) : formatted);
    }
  }

  /**
   * Log warning message
   * @param {string} message - Warning message
   * @param {object} meta - Additional metadata
   */
  warn(message, meta = {}) {
    if (this.level >= LOG_LEVELS.WARN) {
      const formatted = this.formatMessage('WARN', message, meta);
      console.warn(this.enableColors ? colors.yellow(formatted) : formatted);
    }
  }

  /**
   * Log info message
   * @param {string} message - Info message
   * @param {object} meta - Additional metadata
   */
  info(message, meta = {}) {
    if (this.level >= LOG_LEVELS.INFO) {
      const formatted = this.formatMessage('INFO', message, meta);
      console.log(this.enableColors ? colors.blue(formatted) : formatted);
    }
  }

  /**
   * Log debug message
   * @param {string} message - Debug message
   * @param {object} meta - Additional metadata
   */
  debug(message, meta = {}) {
    if (this.level >= LOG_LEVELS.DEBUG) {
      const formatted = this.formatMessage('DEBUG', message, meta);
      console.log(this.enableColors ? colors.gray(formatted) : formatted);
    }
  }

  /**
   * Log verbose message
   * @param {string} message - Verbose message
   * @param {object} meta - Additional metadata
   */
  verbose(message, meta = {}) {
    if (this.level >= LOG_LEVELS.VERBOSE) {
      const formatted = this.formatMessage('VERBOSE', message, meta);
      console.log(this.enableColors ? colors.gray(formatted) : formatted);
    }
  }

  /**
   * Log performance metrics
   * @param {string} operation - Operation name
   * @param {number} duration - Duration in milliseconds
   * @param {object} metrics - Additional metrics
   */
  performance(operation, duration, metrics = {}) {
    if (this.level >= LOG_LEVELS.INFO) {
      const message = `Performance: ${operation} completed in ${duration}ms`;
      const meta = { operation, duration, ...metrics };
      const formatted = this.formatMessage('PERF', message, meta);
      console.log(this.enableColors ? colors.cyan(formatted) : formatted);
    }
  }

  /**
   * Log security events
   * @param {string} event - Security event type
   * @param {string} message - Event message
   * @param {object} meta - Additional metadata
   */
  security(event, message, meta = {}) {
    if (this.level >= LOG_LEVELS.WARN) {
      const formatted = this.formatMessage('SECURITY', `${event}: ${message}`, meta);
      console.log(this.enableColors ? colors.red.bold(formatted) : formatted);
    }
  }
}

/**
 * Default logger instance
 */
const logger = new Logger({
  level: process.env.NULLVOID_LOG_LEVEL || LOG_LEVELS.INFO,
  enableColors: process.env.NULLVOID_NO_COLOR !== 'true',
  timestamp: process.env.NULLVOID_TIMESTAMP === 'true'
});

/**
 * Create a child logger with a specific prefix
 * @param {string} prefix - Logger prefix
 * @param {object} options - Additional options
 * @returns {Logger} Child logger instance
 */
function createLogger(prefix, options = {}) {
  return new Logger({
    ...options,
    prefix: `${logger.prefix}:${prefix}`,
    level: logger.level,
    enableColors: logger.enableColors,
    timestamp: logger.timestamp
  });
}

module.exports = {
  Logger,
  logger,
  createLogger,
  LOG_LEVELS
};
