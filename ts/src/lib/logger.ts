/**
 * Centralized Logging System for NullVoid
 * Provides structured logging with different levels and output formatting
 * Migrated from JavaScript to TypeScript with enhanced type safety
 */

import colors from '../colors';

/**
 * Log levels in order of severity
 */
export const LOG_LEVELS = {
  ERROR: 0,
  WARN: 1,
  INFO: 2,
  DEBUG: 3,
  VERBOSE: 4,
} as const;

export type LogLevel = keyof typeof LOG_LEVELS;
export type LogLevelValue = (typeof LOG_LEVELS)[LogLevel];

/**
 * Logger configuration options
 */
export interface LoggerOptions {
  /** Log level (name or numeric value) */
  level?: LogLevel | LogLevelValue;
  /** Enable colored output */
  enableColors?: boolean;
  /** Logger prefix */
  prefix?: string;
  /** Include timestamp in logs */
  timestamp?: boolean;
}

/**
 * Additional metadata for log entries
 */
export interface LogMetadata {
  [key: string]: unknown;
}

/**
 * Performance metrics for logging
 */
export interface PerformanceMetrics {
  operation: string;
  duration: number;
  [key: string]: unknown;
}

/**
 * Security event information
 */
export interface SecurityEvent {
  event: string;
  message: string;
  metadata?: LogMetadata;
}

/**
 * Logger class for structured logging
 */
export class Logger {
  private level: LogLevelValue;
  private enableColors: boolean;
  private prefix: string;
  private timestamp: boolean;

  constructor(options: LoggerOptions = {}) {
    this.level =
      this.parseLogLevel(options.level) ||
      (process.env['NODE_ENV'] === 'test' ? LOG_LEVELS.ERROR : LOG_LEVELS.INFO);
    this.enableColors = options.enableColors !== false;
    this.prefix = options.prefix || 'NullVoid';
    this.timestamp = options.timestamp !== false;
  }

  /**
   * Parse log level from string or number
   */
  private parseLogLevel(level?: LogLevel | LogLevelValue): LogLevelValue | null {
    if (typeof level === 'string') {
      const upperLevel = level.toUpperCase() as LogLevel;
      return LOG_LEVELS[upperLevel] ?? null;
    } else if (typeof level === 'number') {
      return level;
    }
    return null;
  }

  /**
   * Set the logging level
   * @param level - Log level name or number
   */
  setLevel(level: LogLevel | LogLevelValue): void {
    const parsedLevel = this.parseLogLevel(level);
    if (parsedLevel !== null) {
      this.level = parsedLevel;
    }
  }

  /**
   * Get current log level
   */
  getLevel(): LogLevelValue {
    return this.level;
  }

  /**
   * Check if a log level should be output
   */
  private shouldLog(level: LogLevelValue): boolean {
    return this.level >= level;
  }

  /**
   * Format log message with timestamp and prefix
   * @param level - Log level
   * @param message - Log message
   * @param meta - Additional metadata
   * @returns Formatted log message
   */
  private formatMessage(level: string, message: string, meta: LogMetadata = {}): string {
    const parts: string[] = [];

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
   * Apply color to message if colors are enabled
   */
  private applyColor(message: string, colorFn: (text: string) => string): string {
    return this.enableColors ? colorFn(message) : message;
  }

  /**
   * Log error message
   * @param message - Error message
   * @param meta - Additional metadata
   */
  error(message: string, meta: LogMetadata = {}): void {
    if (this.shouldLog(LOG_LEVELS.ERROR)) {
      const formatted = this.formatMessage('ERROR', message, meta);
      console.error(this.applyColor(formatted, colors.red));
    }
  }

  /**
   * Log warning message
   * @param message - Warning message
   * @param meta - Additional metadata
   */
  warn(message: string, meta: LogMetadata = {}): void {
    if (this.shouldLog(LOG_LEVELS.WARN)) {
      const formatted = this.formatMessage('WARN', message, meta);
      console.warn(this.applyColor(formatted, colors.yellow));
    }
  }

  /**
   * Log info message
   * @param message - Info message
   * @param meta - Additional metadata
   */
  info(message: string, meta: LogMetadata = {}): void {
    if (this.shouldLog(LOG_LEVELS.INFO)) {
      const formatted = this.formatMessage('INFO', message, meta);
      console.log(this.applyColor(formatted, colors.blue));
    }
  }

  /**
   * Log debug message
   * @param message - Debug message
   * @param meta - Additional metadata
   */
  debug(message: string, meta: LogMetadata = {}): void {
    if (this.shouldLog(LOG_LEVELS.DEBUG)) {
      const formatted = this.formatMessage('DEBUG', message, meta);
      console.log(this.applyColor(formatted, colors.gray));
    }
  }

  /**
   * Log verbose message
   * @param message - Verbose message
   * @param meta - Additional metadata
   */
  verbose(message: string, meta: LogMetadata = {}): void {
    if (this.shouldLog(LOG_LEVELS.VERBOSE)) {
      const formatted = this.formatMessage('VERBOSE', message, meta);
      console.log(this.applyColor(formatted, colors.gray));
    }
  }

  /**
   * Log performance metrics
   * @param operation - Operation name
   * @param duration - Duration in milliseconds
   * @param metrics - Additional metrics
   */
  performance(operation: string, duration: number, metrics: LogMetadata = {}): void {
    if (this.shouldLog(LOG_LEVELS.INFO)) {
      const message = `Performance: ${operation} completed in ${duration}ms`;
      const meta: LogMetadata = { operation, duration, ...metrics };
      const formatted = this.formatMessage('PERF', message, meta);
      console.log(this.applyColor(formatted, colors.cyan));
    }
  }

  /**
   * Log security events
   * @param event - Security event type
   * @param message - Event message
   * @param meta - Additional metadata
   */
  security(event: string, message: string, meta: LogMetadata = {}): void {
    if (this.shouldLog(LOG_LEVELS.WARN)) {
      const formatted = this.formatMessage('SECURITY', `${event}: ${message}`, meta);
      console.log(this.applyColor(formatted, (text: string) => colors.red(colors.bold(text))));
    }
  }

  /**
   * Create a child logger with inherited settings
   * @param childPrefix - Additional prefix for child logger
   * @param options - Override options for child logger
   * @returns Child logger instance
   */
  child(childPrefix: string, options: Partial<LoggerOptions> = {}): Logger {
    return new Logger({
      level: this.level,
      enableColors: this.enableColors,
      timestamp: this.timestamp,
      prefix: `${this.prefix}:${childPrefix}`,
      ...options,
    });
  }

  /**
   * Get logger configuration
   */
  getConfig(): LoggerOptions {
    return {
      level: this.level,
      enableColors: this.enableColors,
      prefix: this.prefix,
      timestamp: this.timestamp,
    };
  }
}

/**
 * Default logger instance
 */
export const logger = new Logger({
  level: (process.env['NULLVOID_LOG_LEVEL'] as LogLevel) || LOG_LEVELS.INFO,
  enableColors: process.env['NULLVOID_NO_COLOR'] !== 'true',
  timestamp: process.env['NULLVOID_TIMESTAMP'] === 'true',
});

/**
 * Create a child logger with a specific prefix
 * @param prefix - Logger prefix
 * @param options - Additional options
 * @returns Child logger instance
 */
export function createLogger(prefix: string, options: Partial<LoggerOptions> = {}): Logger {
  const config = logger.getConfig();
  return new Logger({
    ...options,
    prefix: `${config.prefix}:${prefix}`,
    level: config.level as LogLevel | LogLevelValue,
    enableColors: config.enableColors ?? true,
    timestamp: config.timestamp ?? true,
  });
}

/**
 * Create a new logger instance with custom options
 * @param options - Logger options
 * @returns New logger instance
 */
export function createCustomLogger(options: LoggerOptions): Logger {
  return new Logger(options);
}
