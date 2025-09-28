import * as path from 'path';
import * as fs from 'fs';
import { VALIDATION_CONFIG } from './config';

/**
 * Validation error class
 */
export class ValidationError extends Error {
  public field: string;
  public value: any;
  
  constructor(message: string, field: string, value: any) {
    super(message);
    this.name = 'ValidationError';
    this.field = field;
    this.value = value;
  }
}

export interface ValidationRule {
  field: string;
  required?: boolean;
  type?: string;
  minLength?: number;
  maxLength?: number;
  pattern?: RegExp;
  allowedValues?: string[];
  customValidator?: (value: any) => boolean;
}

export interface ValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
  sanitizedValue?: any;
}

export interface ScanOptions {
  maxDepth?: number;
  workers?: number | undefined;
  output?: string;
  verbose?: boolean;
  parallel?: boolean;
  all?: boolean;
}

export interface AllowedExtension {
  extension: string;
  description: string;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH';
}

export interface OutputFormat {
  format: string;
  description: string;
  supported: boolean;
}

/**
 * Input Validator class
 */
export class InputValidator {
  private rules: ValidationRule[];
  
  constructor(rules: ValidationRule[] = []) {
    this.rules = rules;
  }
  
  /**
   * Add validation rule
   */
  addRule(rule: ValidationRule): void {
    this.rules.push(rule);
  }
  
  /**
   * Validate input against rules
   */
  validate(input: any): ValidationResult {
    const result: ValidationResult = {
      isValid: true,
      errors: [],
      warnings: []
    };
    
    for (const rule of this.rules) {
      try {
        this.validateField(input, rule);
      } catch (error: any) {
        result.isValid = false;
        result.errors.push(error.message);
      }
    }
    
    return result;
  }
  
  private validateField(input: any, rule: ValidationRule): void {
    const value = input[rule.field];
    
    // Check required
    if (rule.required && (value === undefined || value === null || value === '')) {
      throw new ValidationError(`Field '${rule.field}' is required`, rule.field, value);
    }
    
    // Skip validation if field is not provided and not required
    if (value === undefined || value === null) {
      return;
    }
    
    // Check type
    if (rule.type && typeof value !== rule.type) {
      throw new ValidationError(`Field '${rule.field}' must be of type ${rule.type}`, rule.field, value);
    }
    
    // Check string length
    if (typeof value === 'string') {
      if (rule.minLength && value.length < rule.minLength) {
        throw new ValidationError(`Field '${rule.field}' must be at least ${rule.minLength} characters long`, rule.field, value);
      }
      
      if (rule.maxLength && value.length > rule.maxLength) {
        throw new ValidationError(`Field '${rule.field}' must be no more than ${rule.maxLength} characters long`, rule.field, value);
      }
      
      // Check pattern
      if (rule.pattern && !rule.pattern.test(value)) {
        throw new ValidationError(`Field '${rule.field}' does not match required pattern`, rule.field, value);
      }
    }
    
    // Check allowed values
    if (rule.allowedValues && !rule.allowedValues.includes(value)) {
      throw new ValidationError(`Field '${rule.field}' must be one of: ${rule.allowedValues.join(', ')}`, rule.field, value);
    }
    
    // Custom validator
    if (rule.customValidator && !rule.customValidator(value)) {
      throw new ValidationError(`Field '${rule.field}' failed custom validation`, rule.field, value);
    }
  }
}

/**
 * Validate package name
 */
export function validatePackageName(name: string): boolean {
  if (!name || typeof name !== 'string') {
    throw new ValidationError('Package name must be a non-empty string', 'packageName', name);
  }

  if (name.length < VALIDATION_CONFIG.PACKAGE_NAME_MIN_LENGTH) {
    throw new ValidationError(`Package name must be at least ${VALIDATION_CONFIG.PACKAGE_NAME_MIN_LENGTH} character long`, 'packageName', name);
  }

  if (name.length > VALIDATION_CONFIG.PACKAGE_NAME_MAX_LENGTH) {
    throw new ValidationError(`Package name must be no more than ${VALIDATION_CONFIG.PACKAGE_NAME_MAX_LENGTH} characters long`, 'packageName', name);
  }

  if (!VALIDATION_CONFIG.PACKAGE_NAME_PATTERN.test(name)) {
    throw new ValidationError('Package name contains invalid characters. Only letters, numbers, dots, underscores, and hyphens are allowed', 'packageName', name);
  }

  // Additional npm-specific rules
  if (name.startsWith('.') || name.startsWith('_')) {
    throw new ValidationError('Package name cannot start with a dot or underscore', 'packageName', name);
  }

  if (name.includes('..')) {
    throw new ValidationError('Package name cannot contain consecutive dots', 'packageName', name);
  }

  return true;
}

/**
 * Validate package version
 */
export function validatePackageVersion(version: string): boolean {
  if (!version || typeof version !== 'string') {
    throw new ValidationError('Package version must be a non-empty string', 'packageVersion', version);
  }

  // Basic semver pattern (simplified)
  if (!VALIDATION_CONFIG.SEMVER_PATTERN.test(version)) {
    throw new ValidationError('Package version must be a valid semver string', 'packageVersion', version);
  }

  return true;
}

/**
 * Validate directory path
 */
export function validateDirectoryPath(dirPath: string): boolean {
  if (!dirPath || typeof dirPath !== 'string') {
    throw new ValidationError('Directory path must be a non-empty string', 'directoryPath', dirPath);
  }

  // Check for path traversal attempts
  if (dirPath.includes('..') || dirPath.includes('~')) {
    throw new ValidationError('Directory path contains potentially dangerous characters', 'directoryPath', dirPath);
  }

  // Check if path exists and is a directory
  try {
    const resolvedPath = path.resolve(dirPath);
    const stats = fs.statSync(resolvedPath);
    
    if (!stats.isDirectory()) {
      throw new ValidationError('Path exists but is not a directory', 'directoryPath', dirPath);
    }
  } catch (error: any) {
    if (error instanceof ValidationError) {
      throw error;
    }
    throw new ValidationError(`Directory path does not exist or is not accessible: ${error.message}`, 'directoryPath', dirPath);
  }

  return true;
}

/**
 * Validate scan options
 */
export function validateScanOptions(options: ScanOptions): boolean {
  if (!options || typeof options !== 'object') {
    throw new ValidationError('Scan options must be an object', 'scanOptions', options);
  }

  // Validate maxDepth
  if (options.maxDepth !== undefined) {
    if (typeof options.maxDepth !== 'number' || !Number.isInteger(options.maxDepth) || options.maxDepth < 0 || options.maxDepth > 10) {
      throw new ValidationError('maxDepth must be an integer between 0 and 10', 'maxDepth', options.maxDepth);
    }
  }

  // Validate workers count
  if (options.workers !== undefined) {
    if (typeof options.workers !== 'number' || !Number.isInteger(options.workers) || options.workers < 1 || options.workers > 16) {
      throw new ValidationError('workers must be an integer between 1 and 16', 'workers', options.workers);
    }
  }

  // Validate output format
  if (options.output !== undefined) {
    if (!VALIDATION_CONFIG.VALID_OUTPUT_FORMATS.includes(options.output as any)) {
      throw new ValidationError(`output must be one of: ${VALIDATION_CONFIG.VALID_OUTPUT_FORMATS.join(', ')}`, 'output', options.output);
    }
  }

  return true;
}

/**
 * Validate file path
 */
export function validateFilePath(filePath: string): boolean {
  if (!filePath || typeof filePath !== 'string') {
    throw new ValidationError('File path must be a non-empty string', 'filePath', filePath);
  }

  // Check for path traversal attempts
  if (filePath.includes('..') || filePath.includes('~')) {
    throw new ValidationError('File path contains potentially dangerous characters', 'filePath', filePath);
  }

  // Check file extension
  const ext = path.extname(filePath).toLowerCase();
  
  if (ext && !VALIDATION_CONFIG.ALLOWED_EXTENSIONS.includes(ext as any)) {
    throw new ValidationError(`File extension '${ext}' is not allowed. Allowed extensions: ${VALIDATION_CONFIG.ALLOWED_EXTENSIONS.join(', ')}`, 'filePath', filePath);
  }

  return true;
}

/**
 * Sanitize input string
 */
export function sanitizeInput(input: string, maxLength: number = 1000): string {
  if (typeof input !== 'string') {
    return '';
  }

  // Remove control characters and limit length
  // eslint-disable-next-line no-control-regex
  return input
    .replace(/[\u0000-\u001F\u007F-\u009F]/g, '') // Remove control characters
    .substring(0, maxLength)
    .trim();
}

/**
 * Validate and sanitize package name
 */
export function validateAndSanitizePackageName(name: string): string {
  const sanitized = sanitizeInput(name, VALIDATION_CONFIG.PACKAGE_NAME_MAX_LENGTH);
  validatePackageName(sanitized);
  return sanitized;
}

/**
 * Validate URL
 */
export function validateUrl(url: string): boolean {
  if (!url || typeof url !== 'string') {
    throw new ValidationError('URL must be a non-empty string', 'url', url);
  }

  try {
    new URL(url);
    return true;
  } catch {
    throw new ValidationError('Invalid URL format', 'url', url);
  }
}

/**
 * Validate email
 */
export function validateEmail(email: string): boolean {
  if (!email || typeof email !== 'string') {
    throw new ValidationError('Email must be a non-empty string', 'email', email);
  }

  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailPattern.test(email)) {
    throw new ValidationError('Invalid email format', 'email', email);
  }

  return true;
}

/**
 * Check if input contains suspicious patterns
 */
export function isSuspiciousPattern(input: string): boolean {
  const suspiciousPatterns = [
    /eval\s*\(/i,
    /Function\s*\(/i,
    /setTimeout\s*\(/i,
    /setInterval\s*\(/i,
    /document\.write/i,
    /innerHTML\s*=/i,
    /outerHTML\s*=/i,
    /\.replace\s*\(/i,
    /\.substring\s*\(/i,
    /\.slice\s*\(/i
  ];

  return suspiciousPatterns.some(pattern => pattern.test(input));
}

/**
 * Check if input contains dangerous patterns
 */
export function isDangerousPattern(input: string): boolean {
  const dangerousPatterns = [
    /require\s*\(/i,
    /import\s*\(/i,
    /process\.exit/i,
    /process\.kill/i,
    /child_process/i,
    /fs\.unlink/i,
    /fs\.rmdir/i,
    /fs\.rm/i,
    /exec\s*\(/i,
    /spawn\s*\(/i
  ];

  return dangerousPatterns.some(pattern => pattern.test(input));
}

/**
 * Check if input contains malicious patterns
 */
export function containsMaliciousPatterns(input: string): boolean {
  const maliciousPatterns = [
    /base64/i,
    /atob\s*\(/i,
    /btoa\s*\(/i,
    /String\.fromCharCode/i,
    /decodeURIComponent/i,
    /encodeURIComponent/i,
    /unescape\s*\(/i,
    /escape\s*\(/i,
    /_0x[a-f0-9]+/i,
    /\\x[0-9a-f]{2}/i
  ];

  return maliciousPatterns.some(pattern => pattern.test(input));
}