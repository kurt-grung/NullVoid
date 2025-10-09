import { Threat, createThreat } from '../types/core';
import * as path from 'path';
import * as fs from 'fs';
import { VALIDATION_CONFIG } from './config';

export interface PathSecurityConfig {
  maxPathLength: number;
  allowedExtensions: string[];
  blockedPaths: string[];
  traversalPatterns: RegExp[];
  injectionPatterns: RegExp[];
}

export interface PathErrorDetails {
  originalPath: string;
  resolvedPath?: string;
  errorType: 'TRAVERSAL' | 'INJECTION' | 'INVALID_EXTENSION' | 'ACCESS_DENIED';
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export interface PathValidationResult {
  isValid: boolean;
  sanitizedPath?: string;
  errors: string[];
  warnings: string[];
  threats: Threat[];
}

/**
 * Path Traversal Error
 */
export class PathTraversalError extends Error {
  public originalPath: string;
  public resolvedPath: string;
  
  constructor(message: string, originalPath: string, resolvedPath: string) {
    super(message);
    this.name = 'PathTraversalError';
    this.originalPath = originalPath;
    this.resolvedPath = resolvedPath;
  }
}

/**
 * Command Injection Error
 */
export class CommandInjectionError extends Error {
  public suspiciousPattern: string;
  public inputPath: string;
  
  constructor(message: string, inputPath: string, suspiciousPattern: string) {
    super(message);
    this.name = 'CommandInjectionError';
    this.inputPath = inputPath;
    this.suspiciousPattern = suspiciousPattern;
  }
}

/**
 * Path Validation Error
 */
export class PathValidationError extends Error {
  public validationType: string;
  public inputPath: string;
  
  constructor(message: string, inputPath: string, validationType: string) {
    super(message);
    this.name = 'PathValidationError';
    this.inputPath = inputPath;
    this.validationType = validationType;
  }
}

// Path security configuration
const PATH_SECURITY_CONFIG: PathSecurityConfig = {
  maxPathLength: 4096,
  allowedExtensions: ['.js', '.mjs', '.ts', '.jsx', '.tsx', '.json'],
  blockedPaths: [
    '/etc/passwd',
    '/etc/shadow',
    '/proc/',
    '/sys/',
    'C:\\Windows\\System32',
    'C:\\Windows\\SysWOW64'
  ],
  traversalPatterns: [
    /\.\.\//g,
    /\.\.\\/g,
    /\.\.%2f/gi,
    /\.\.%5c/gi,
    /\.\.%252f/gi,
    /\.\.%255c/gi
  ],
  injectionPatterns: [
    /[;&|`$(){}[\]]/g,
    /\$\(/g,
    /`[^`]*`/g,
    /\$\{[^}]*\}/g
  ]
};

/**
 * Validate path for security issues
 */
export function validatePath(inputPath: string): PathValidationResult {
  const result: PathValidationResult = {
    isValid: true,
    errors: [],
    warnings: [],
    threats: []
  };

  if (!inputPath || typeof inputPath !== 'string') {
    result.isValid = false;
    result.errors.push('Path must be a non-empty string');
    return result;
  }

  // Check path length
  if (inputPath.length > PATH_SECURITY_CONFIG.maxPathLength) {
    result.isValid = false;
    result.errors.push(`Path exceeds maximum length of ${PATH_SECURITY_CONFIG.maxPathLength} characters`);
    result.threats.push(createThreat(
      'PATH_VALIDATION_ERROR',
      'Path length exceeds security limits',
      inputPath,
      path.basename(inputPath),
      'MEDIUM',
      'Extremely long paths may indicate path traversal attempts',
      { pathLength: inputPath.length, confidence: 0.7 }
    ));
  }

  // Check for path traversal patterns
  for (const pattern of PATH_SECURITY_CONFIG.traversalPatterns) {
    if (pattern.test(inputPath)) {
      result.isValid = false;
      result.errors.push('Path contains traversal patterns');
      result.threats.push(createThreat(
        'PATH_TRAVERSAL',
        'Path traversal attempt detected',
        inputPath,
        path.basename(inputPath),
        'HIGH',
        'Path contains patterns commonly used in directory traversal attacks',
        { pattern: pattern.source, confidence: 0.9 }
      ));
      break;
    }
  }

  // Check for command injection patterns
  for (const pattern of PATH_SECURITY_CONFIG.injectionPatterns) {
    if (pattern.test(inputPath)) {
      result.isValid = false;
      result.errors.push('Path contains potentially dangerous characters');
      result.threats.push(createThreat(
        'COMMAND_INJECTION',
        'Command injection attempt detected in path',
        inputPath,
        path.basename(inputPath),
        'CRITICAL',
        'Path contains characters that could be used for command injection',
        { pattern: pattern.source, confidence: 0.8 }
      ));
      break;
    }
  }

  // Check for blocked paths
  for (const blockedPath of PATH_SECURITY_CONFIG.blockedPaths) {
    if (inputPath.includes(blockedPath)) {
      result.isValid = false;
      result.errors.push(`Access to path '${blockedPath}' is not allowed`);
      result.threats.push(createThreat(
        'PATH_VALIDATION_ERROR',
        'Attempt to access restricted system path',
        inputPath,
        path.basename(inputPath),
        'HIGH',
        'Attempted access to sensitive system directories',
        { blockedPath, confidence: 0.9 }
      ));
    }
  }

  // Sanitize path if valid
  if (result.isValid) {
    try {
      result.sanitizedPath = path.normalize(inputPath);
    } catch (error: unknown) {
      result.isValid = false;
      result.errors.push(`Path normalization failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  return result;
}

/**
 * Safely read a file with path validation
 */
export async function safeReadFile(filePath: string): Promise<string> {
  const validation = validatePath(filePath);
  
  if (!validation.isValid) {
    throw new PathValidationError(
      `Invalid file path: ${validation.errors.join(', ')}`,
      filePath,
      'FILE_READ'
    );
  }

  const safePath = validation.sanitizedPath!;
  
  try {
    const resolvedPath = path.resolve(safePath);
    const stats = await fs.promises.stat(resolvedPath);
    
    if (!stats.isFile()) {
      throw new PathValidationError('Path is not a file', filePath, 'FILE_TYPE');
    }
    
    return await fs.promises.readFile(resolvedPath, 'utf8');
  } catch (error: unknown) {
    if (error instanceof PathValidationError) {
      throw error;
    }
    throw new PathValidationError(`Failed to read file: ${error instanceof Error ? error.message : String(error)}`, filePath, 'FILE_ACCESS');
  }
}

/**
 * Safely read a directory with path validation
 */
export async function safeReadDir(dirPath: string): Promise<string[]> {
  const validation = validatePath(dirPath);
  
  if (!validation.isValid) {
    throw new PathValidationError(
      `Invalid directory path: ${validation.errors.join(', ')}`,
      dirPath,
      'DIR_READ'
    );
  }

  const safePath = validation.sanitizedPath!;
  
  try {
    const resolvedPath = path.resolve(safePath);
    const stats = await fs.promises.stat(resolvedPath);
    
    if (!stats.isDirectory()) {
      throw new PathValidationError('Path is not a directory', dirPath, 'DIR_TYPE');
    }
    
    return await fs.promises.readdir(resolvedPath);
  } catch (error: unknown) {
    if (error instanceof PathValidationError) {
      throw error;
    }
    throw new PathValidationError(`Failed to read directory: ${error instanceof Error ? error.message : String(error)}`, dirPath, 'DIR_ACCESS');
  }
}

/**
 * Safely join paths
 */
export function safePathJoin(...segments: string[]): string {
  if (segments.length === 0) {
    throw new PathValidationError('No path segments provided', '', 'PATH_JOIN');
  }

  // Validate each segment
  for (const segment of segments) {
    const validation = validatePath(segment);
    if (!validation.isValid) {
      throw new PathValidationError(
        `Invalid path segment '${segment}': ${validation.errors.join(', ')}`,
        segment,
        'PATH_SEGMENT'
      );
    }
  }

  const joinedPath = path.join(...segments);
  const finalValidation = validatePath(joinedPath);
  
  if (!finalValidation.isValid) {
    throw new PathValidationError(
      `Invalid joined path: ${finalValidation.errors.join(', ')}`,
      joinedPath,
      'PATH_JOIN_RESULT'
    );
  }

  return finalValidation.sanitizedPath!;
}

/**
 * Check if file type is allowed
 */
export function isAllowedFileType(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  return PATH_SECURITY_CONFIG.allowedExtensions.includes(ext);
}

/**
 * Get safe file paths from a directory
 */
export async function getSafeFilePaths(dirPath: string, recursive: boolean = false): Promise<string[]> {
  const validation = validatePath(dirPath);
  
  if (!validation.isValid) {
    throw new PathValidationError(
      `Invalid directory path: ${validation.errors.join(', ')}`,
      dirPath,
      'DIR_SCAN'
    );
  }

  const safePaths: string[] = [];
  const safeDirPath = validation.sanitizedPath!;

  try {
    const entries = await safeReadDir(safeDirPath);
    
    for (const entry of entries) {
      const entryPath = safePathJoin(safeDirPath, entry);
      
      try {
        const stats = await fs.promises.stat(entryPath);
        
        if (stats.isFile() && isAllowedFileType(entryPath)) {
          safePaths.push(entryPath);
        } else if (stats.isDirectory() && recursive) {
          const subPaths = await getSafeFilePaths(entryPath, recursive);
          safePaths.push(...subPaths);
        }
      } catch {
        // Skip entries that can't be accessed
        continue;
      }
    }
  } catch (error: unknown) {
    throw new PathValidationError(`Failed to scan directory: ${error instanceof Error ? error.message : String(error)}`, dirPath, 'DIR_SCAN');
  }

  return safePaths;
}

/**
 * Validate package name for path security
 */
export function validatePackageName(packageName: string): boolean {
  if (!packageName || typeof packageName !== 'string') {
    return false;
  }

  // Check for path traversal in package name
  for (const pattern of PATH_SECURITY_CONFIG.traversalPatterns) {
    if (pattern.test(packageName)) {
      return false;
    }
  }

  // Check for command injection patterns
  for (const pattern of PATH_SECURITY_CONFIG.injectionPatterns) {
    if (pattern.test(packageName)) {
      return false;
    }
  }

  // Check against npm package name rules
  return VALIDATION_CONFIG.PACKAGE_NAME_PATTERN.test(packageName);
}

/**
 * Path Security Manager class
 */
export class PathSecurityManager {
  private config: PathSecurityConfig;

  constructor(config: Partial<PathSecurityConfig> = {}) {
    this.config = {
      ...PATH_SECURITY_CONFIG,
      ...config
    };
  }

  validatePath(inputPath: string): PathValidationResult {
    return validatePath(inputPath);
  }

  async safeReadFile(filePath: string): Promise<string> {
    return await safeReadFile(filePath);
  }

  async safeReadDir(dirPath: string): Promise<string[]> {
    return await safeReadDir(dirPath);
  }

  safePathJoin(...segments: string[]): string {
    return safePathJoin(...segments);
  }

  isAllowedFileType(filePath: string): boolean {
    return isAllowedFileType(filePath);
  }

  async getSafeFilePaths(dirPath: string, recursive: boolean = false): Promise<string[]> {
    return await getSafeFilePaths(dirPath, recursive);
  }

  validatePackageName(packageName: string): boolean {
    return validatePackageName(packageName);
  }

  updateConfig(newConfig: Partial<PathSecurityConfig>): void {
    this.config = { ...this.config, ...newConfig };
  }

  getConfig(): PathSecurityConfig {
    return { ...this.config };
  }
}

// Export default instance
export const pathSecurityManager = new PathSecurityManager();