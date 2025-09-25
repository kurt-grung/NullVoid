/**
 * Input Validation Utilities for NullVoid
 * Provides validation for package names, paths, and other inputs
 */

const path = require('path');
const fs = require('fs');

/**
 * Validation error class
 */
class ValidationError extends Error {
  constructor(message, field, value) {
    super(message);
    this.name = 'ValidationError';
    this.field = field;
    this.value = value;
  }
}

/**
 * Package name validation rules
 */
const PACKAGE_NAME_PATTERN = /^[a-zA-Z0-9._-]+$/;
const PACKAGE_NAME_MAX_LENGTH = 214;
const PACKAGE_NAME_MIN_LENGTH = 1;

/**
 * Validate package name
 * @param {string} name - Package name to validate
 * @returns {boolean} True if valid
 * @throws {ValidationError} If validation fails
 */
function validatePackageName(name) {
  if (!name || typeof name !== 'string') {
    throw new ValidationError('Package name must be a non-empty string', 'packageName', name);
  }

  if (name.length < PACKAGE_NAME_MIN_LENGTH) {
    throw new ValidationError(`Package name must be at least ${PACKAGE_NAME_MIN_LENGTH} character long`, 'packageName', name);
  }

  if (name.length > PACKAGE_NAME_MAX_LENGTH) {
    throw new ValidationError(`Package name must be no more than ${PACKAGE_NAME_MAX_LENGTH} characters long`, 'packageName', name);
  }

  if (!PACKAGE_NAME_PATTERN.test(name)) {
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
 * @param {string} version - Version string to validate
 * @returns {boolean} True if valid
 * @throws {ValidationError} If validation fails
 */
function validatePackageVersion(version) {
  if (!version || typeof version !== 'string') {
    throw new ValidationError('Package version must be a non-empty string', 'packageVersion', version);
  }

  // Basic semver pattern (simplified)
  const semverPattern = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;
  
  if (!semverPattern.test(version)) {
    throw new ValidationError('Package version must be a valid semver string', 'packageVersion', version);
  }

  return true;
}

/**
 * Validate directory path
 * @param {string} dirPath - Directory path to validate
 * @returns {boolean} True if valid
 * @throws {ValidationError} If validation fails
 */
function validateDirectoryPath(dirPath) {
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
  } catch (error) {
    if (error instanceof ValidationError) {
      throw error;
    }
    throw new ValidationError(`Directory path does not exist or is not accessible: ${error.message}`, 'directoryPath', dirPath);
  }

  return true;
}

/**
 * Validate scan options
 * @param {object} options - Scan options to validate
 * @returns {boolean} True if valid
 * @throws {ValidationError} If validation fails
 */
function validateScanOptions(options) {
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
    const validFormats = ['json', 'table', 'yaml'];
    if (!validFormats.includes(options.output)) {
      throw new ValidationError(`output must be one of: ${validFormats.join(', ')}`, 'output', options.output);
    }
  }

  return true;
}

/**
 * Validate file path
 * @param {string} filePath - File path to validate
 * @returns {boolean} True if valid
 * @throws {ValidationError} If validation fails
 */
function validateFilePath(filePath) {
  if (!filePath || typeof filePath !== 'string') {
    throw new ValidationError('File path must be a non-empty string', 'filePath', filePath);
  }

  // Check for path traversal attempts
  if (filePath.includes('..') || filePath.includes('~')) {
    throw new ValidationError('File path contains potentially dangerous characters', 'filePath', filePath);
  }

  // Check file extension
  const ext = path.extname(filePath).toLowerCase();
  const allowedExtensions = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.json', '.yml', '.yaml'];
  
  if (ext && !allowedExtensions.includes(ext)) {
    throw new ValidationError(`File extension '${ext}' is not allowed. Allowed extensions: ${allowedExtensions.join(', ')}`, 'filePath', filePath);
  }

  return true;
}

/**
 * Sanitize input string
 * @param {string} input - Input string to sanitize
 * @param {number} maxLength - Maximum length allowed
 * @returns {string} Sanitized string
 */
function sanitizeInput(input, maxLength = 1000) {
  if (typeof input !== 'string') {
    return '';
  }

  // Remove control characters and limit length
  return input
    .replace(/[\x00-\x1F\x7F-\x9F]/g, '') // Remove control characters
    .substring(0, maxLength)
    .trim();
}

/**
 * Validate and sanitize package name
 * @param {string} name - Package name to validate and sanitize
 * @returns {string} Sanitized package name
 * @throws {ValidationError} If validation fails
 */
function validateAndSanitizePackageName(name) {
  const sanitized = sanitizeInput(name, PACKAGE_NAME_MAX_LENGTH);
  validatePackageName(sanitized);
  return sanitized;
}

module.exports = {
  ValidationError,
  validatePackageName,
  validatePackageVersion,
  validateDirectoryPath,
  validateScanOptions,
  validateFilePath,
  sanitizeInput,
  validateAndSanitizePackageName,
  PACKAGE_NAME_PATTERN,
  PACKAGE_NAME_MAX_LENGTH,
  PACKAGE_NAME_MIN_LENGTH
};
