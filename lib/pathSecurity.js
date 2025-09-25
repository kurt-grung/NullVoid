/**
 * Secure Path Validation and File Operations
 * Prevents path traversal attacks and ensures safe file access
 */

const path = require('path');
const fs = require('fs');

/**
 * Custom error classes for path validation
 */
class PathTraversalError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = 'PathTraversalError';
    this.details = details;
  }
}

class CommandInjectionError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = 'CommandInjectionError';
    this.details = details;
  }
}

/**
 * Security configuration for path validation
 */
const PATH_SECURITY_CONFIG = {
  maxPathLength: 4096, // Maximum path length
  allowedExtensions: ['.js', '.mjs', '.ts', '.json', '.yml', '.yaml'],
  blockedPatterns: [
    /\.\./, // Path traversal
    /\/\//, // Double slashes
    /\\\\/, // Double backslashes
    /[<>:"|?*]/, // Invalid characters
    /^\./, // Hidden files (unless explicitly allowed)
    /node_modules\/\.\./, // Escaping node_modules
    /\.git/, // Git directories
    /\.env/, // Environment files
    /package-lock\.json/, // Lock files
    /yarn\.lock/ // Yarn lock files
  ],
  allowedDirectories: [
    'node_modules',
    'lib',
    'src',
    'test',
    'tests',
    'spec',
    'specs'
  ]
};

/**
 * Custom error class for path validation errors
 */
class PathValidationError extends Error {
  constructor(message, code, details = {}) {
    super(message);
    this.name = 'PathValidationError';
    this.code = code;
    this.details = details;
  }
}

/**
 * Validate and sanitize file path
 * @param {string} inputPath - Input path to validate
 * @param {string} basePath - Base directory for relative paths
 * @returns {string} Validated and normalized path
 * @throws {PathValidationError} If path is invalid
 */
function validatePath(inputPath, basePath = process.cwd()) {
  if (!inputPath || typeof inputPath !== 'string') {
    throw new PathValidationError('Path must be a non-empty string', 'INVALID_INPUT');
  }
  
  // Check path length
  if (inputPath.length > PATH_SECURITY_CONFIG.maxPathLength) {
    throw new PathValidationError(
      `Path too long: ${inputPath.length} characters (max: ${PATH_SECURITY_CONFIG.maxPathLength})`,
      'PATH_TOO_LONG'
    );
  }
  
  // Remove dangerous characters
  const sanitizedPath = inputPath.replace(/[;&|`$(){}[\]<>]/g, '');
  if (sanitizedPath !== inputPath) {
    throw new PathValidationError(
      'Path contains potentially dangerous characters',
      'DANGEROUS_CHARACTERS',
      { original: inputPath, sanitized: sanitizedPath }
    );
  }
  
  // Normalize path
  const normalizedPath = path.normalize(inputPath);
  
    // Check for blocked patterns
    for (const pattern of PATH_SECURITY_CONFIG.blockedPatterns) {
      if (pattern.test(normalizedPath)) {
        throw new PathTraversalError(
          `Path contains blocked pattern: ${pattern}`,
          { path: normalizedPath, pattern: pattern.toString() }
        );
      }
    }
  
  // Resolve to absolute path
  const absolutePath = path.resolve(basePath, normalizedPath);
  
  // Ensure path is within allowed boundaries
  const baseAbsolute = path.resolve(basePath);
  if (!absolutePath.startsWith(baseAbsolute)) {
    throw new PathTraversalError(
      'Path traversal attempt detected',
      { 
        inputPath: inputPath,
        resolvedPath: absolutePath,
        basePath: baseAbsolute
      }
    );
  }
  
  return absolutePath;
}

/**
 * Safely read file with path validation
 * @param {string} filePath - Path to file
 * @param {string} encoding - File encoding (default: 'utf8')
 * @param {string} basePath - Base directory for validation
 * @returns {string} File content
 * @throws {PathValidationError} If path is invalid
 */
function safeReadFile(filePath, encoding = 'utf8', basePath = process.cwd()) {
  const validatedPath = validatePath(filePath, basePath);
  
  // Check if file exists
  if (!fs.existsSync(validatedPath)) {
    throw new PathValidationError(
      `File does not exist: ${validatedPath}`,
      'FILE_NOT_FOUND',
      { path: validatedPath }
    );
  }
  
  // Check if it's actually a file
  const stats = fs.statSync(validatedPath);
  if (!stats.isFile()) {
    throw new PathValidationError(
      `Path is not a file: ${validatedPath}`,
      'NOT_A_FILE',
      { path: validatedPath, stats: stats }
    );
  }
  
  // Check file size (prevent reading huge files)
  const maxFileSize = 10 * 1024 * 1024; // 10MB
  if (stats.size > maxFileSize) {
    throw new PathValidationError(
      `File too large: ${stats.size} bytes (max: ${maxFileSize})`,
      'FILE_TOO_LARGE',
      { path: validatedPath, size: stats.size, maxSize: maxFileSize }
    );
  }
  
  try {
    return fs.readFileSync(validatedPath, encoding);
  } catch (error) {
    throw new PathValidationError(
      `Failed to read file: ${error.message}`,
      'READ_ERROR',
      { path: validatedPath, originalError: error.message }
    );
  }
}

/**
 * Safely read directory with path validation
 * @param {string} dirPath - Path to directory
 * @param {string} basePath - Base directory for validation
 * @returns {Array} Directory contents
 * @throws {PathValidationError} If path is invalid
 */
function safeReadDir(dirPath, basePath = process.cwd()) {
  const validatedPath = validatePath(dirPath, basePath);
  
  // Check if directory exists
  if (!fs.existsSync(validatedPath)) {
    throw new PathValidationError(
      `Directory does not exist: ${validatedPath}`,
      'DIRECTORY_NOT_FOUND',
      { path: validatedPath }
    );
  }
  
  // Check if it's actually a directory
  const stats = fs.statSync(validatedPath);
  if (!stats.isDirectory()) {
    throw new PathValidationError(
      `Path is not a directory: ${validatedPath}`,
      'NOT_A_DIRECTORY',
      { path: validatedPath, stats: stats }
    );
  }
  
  try {
    const items = fs.readdirSync(validatedPath);
    
    // Filter out dangerous items
    return items.filter(item => {
      // Skip hidden files and directories
      if (item.startsWith('.')) return false;
      
      // Skip dangerous files
      const dangerousFiles = [
        'package-lock.json',
        'yarn.lock',
        '.env',
        '.env.local',
        '.env.production',
        '.git',
        '.gitignore',
        '.DS_Store',
        'Thumbs.db'
      ];
      
      if (dangerousFiles.includes(item)) return false;
      
      return true;
    });
  } catch (error) {
    throw new PathValidationError(
      `Failed to read directory: ${error.message}`,
      'READ_DIR_ERROR',
      { path: validatedPath, originalError: error.message }
    );
  }
}

/**
 * Safely join paths with validation
 * @param {string} basePath - Base path
 * @param {...string} paths - Additional paths to join
 * @returns {string} Joined and validated path
 * @throws {PathValidationError} If resulting path is invalid
 */
function safePathJoin(basePath, ...paths) {
  const joinedPath = path.join(basePath, ...paths);
  return validatePath(joinedPath, basePath);
}

/**
 * Check if file extension is allowed
 * @param {string} filePath - File path to check
 * @returns {boolean} True if extension is allowed
 */
function isAllowedFileType(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  return PATH_SECURITY_CONFIG.allowedExtensions.includes(ext);
}

/**
 * Get safe file paths from directory
 * @param {string} dirPath - Directory to scan
 * @param {string} basePath - Base directory for validation
 * @returns {Array} Array of safe file paths
 */
function getSafeFilePaths(dirPath, basePath = process.cwd()) {
  const safePaths = [];
  
  try {
    const items = safeReadDir(dirPath, basePath);
    
    for (const item of items) {
      const itemPath = path.join(dirPath, item);
      const validatedPath = validatePath(itemPath, basePath);
      
      try {
        const stats = fs.statSync(validatedPath);
        
        if (stats.isFile() && isAllowedFileType(validatedPath)) {
          safePaths.push(validatedPath);
        } else if (stats.isDirectory()) {
          // Recursively get files from subdirectories
          const subPaths = getSafeFilePaths(validatedPath, basePath);
          safePaths.push(...subPaths);
        }
      } catch (error) {
        // Skip files that can't be accessed
        console.warn(`Warning: Cannot access ${validatedPath}: ${error.message}`);
      }
    }
  } catch (error) {
    if (error instanceof PathValidationError) {
      throw error;
    }
    console.warn(`Warning: Cannot read directory ${dirPath}: ${error.message}`);
  }
  
  return safePaths;
}

/**
 * Validate package name format
 * @param {string} packageName - Package name to validate
 * @returns {boolean} True if valid
 * @throws {PathValidationError} If package name is invalid
 */
function validatePackageName(packageName) {
  if (!packageName || typeof packageName !== 'string') {
    throw new PathValidationError('Package name must be a non-empty string', 'INVALID_PACKAGE_NAME');
  }
  
  // npm package name validation regex
  const validPackageName = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/i;
  
  if (!validPackageName.test(packageName)) {
    throw new CommandInjectionError(
      `Invalid package name format: ${packageName}`,
      { packageName: packageName }
    );
  }
  
  // Check for suspicious patterns
  const suspiciousPatterns = [
    /malware/i,
    /virus/i,
    /trojan/i,
    /backdoor/i,
    /hack/i,
    /crack/i,
    /keygen/i,
    /[a-z0-9]{32,}/, // Random-looking names
    /^[0-9]+$/ // Only numbers
  ];
  
  for (const pattern of suspiciousPatterns) {
    if (pattern.test(packageName)) {
      throw new PathValidationError(
        `Suspicious package name pattern: ${packageName}`,
        'SUSPICIOUS_PACKAGE_NAME',
        { packageName: packageName, pattern: pattern.toString() }
      );
    }
  }
  
  return true;
}

module.exports = {
  validatePath,
  safeReadFile,
  safeReadDir,
  safePathJoin,
  isAllowedFileType,
  getSafeFilePaths,
  validatePackageName,
  PathValidationError,
  PathTraversalError,
  CommandInjectionError,
  PATH_SECURITY_CONFIG
};
