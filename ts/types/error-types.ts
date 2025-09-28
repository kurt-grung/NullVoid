/**
 * Error-specific type definitions
 */

import { SeverityLevel } from './core';

export class NullVoidError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly severity: SeverityLevel = 'MEDIUM'
  ) {
    super(message);
    this.name = 'NullVoidError';
  }
}

export class SecurityError extends NullVoidError {
  constructor(message: string, code: string = 'SECURITY_ERROR') {
    super(message, code, 'HIGH');
    this.name = 'SecurityError';
  }
}

export class ValidationError extends NullVoidError {
  constructor(message: string, code: string = 'VALIDATION_ERROR') {
    super(message, code, 'MEDIUM');
    this.name = 'ValidationError';
  }
}

export class NetworkError extends NullVoidError {
  constructor(message: string, code: string = 'NETWORK_ERROR') {
    super(message, code, 'LOW');
    this.name = 'NetworkError';
  }
}

export class FileSystemError extends NullVoidError {
  constructor(message: string, code: string = 'FILESYSTEM_ERROR') {
    super(message, code, 'MEDIUM');
    this.name = 'FileSystemError';
  }
}

export class TimeoutError extends NullVoidError {
  constructor(message: string, code: string = 'TIMEOUT_ERROR') {
    super(message, code, 'LOW');
    this.name = 'TimeoutError';
  }
}

export class CacheError extends NullVoidError {
  constructor(message: string, code: string = 'CACHE_ERROR') {
    super(message, code, 'LOW');
    this.name = 'CacheError';
  }
}
