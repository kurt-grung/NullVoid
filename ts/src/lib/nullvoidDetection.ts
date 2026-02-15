/**
 * NullVoid Code Detection Utility
 * Centralized logic for identifying NullVoid's own code vs external packages
 * Migrated from JavaScript to TypeScript with enhanced type safety
 */

import { DETECTION_PATTERNS } from './config';

/**
 * Detection options interface
 */
export interface DetectionOptions {
  includeTestFiles?: boolean;
  strictMode?: boolean;
  customPatterns?: string[];
}

/**
 * Detection result interface
 */
export interface DetectionResult {
  isNullVoidCode: boolean;
  isTestFile: boolean;
  fileName: string;
  matchedPattern?: string;
  confidence: number;
}

/**
 * Check if a given package name or file path belongs to NullVoid's own codebase
 * @param packageName - Package name or file path to check
 * @returns True if this is NullVoid's own code
 */
export function isNullVoidCode(packageName: string): boolean {
  if (!packageName || typeof packageName !== 'string') {
    return false;
  }

  // Extract filename for more precise matching
  const fileName = packageName.split('/').pop() || packageName.split('\\').pop() || packageName;

  // Check for specific NullVoid project files
  const nullVoidFiles = DETECTION_PATTERNS.NULLVOID_FILES;

  // Check if filename matches NullVoid files
  if (nullVoidFiles.includes(fileName)) {
    return true;
  }

  // Check for NullVoid directory structure (more specific)
  if (
    packageName.includes('/NullVoid/') &&
    (packageName.includes('/NullVoid/lib/') ||
      packageName.includes('/NullVoid/bin/') ||
      packageName.includes('/NullVoid/scripts/') ||
      packageName.includes('/NullVoid/src/') ||
      packageName.includes('/NullVoid/ml-model/') ||
      packageName.includes('/NullVoid/scan.js') ||
      packageName.includes('/NullVoid/scan.ts') ||
      packageName.includes('/NullVoid/package.json'))
  ) {
    return true;
  }

  if (
    packageName.includes('\\NullVoid\\') &&
    (packageName.includes('\\NullVoid\\lib\\') ||
      packageName.includes('\\NullVoid\\bin\\') ||
      packageName.includes('\\NullVoid\\scripts\\') ||
      packageName.includes('\\NullVoid\\src\\') ||
      packageName.includes('\\NullVoid\\ml-model\\') ||
      packageName.includes('\\NullVoid\\scan.js') ||
      packageName.includes('\\NullVoid\\scan.ts') ||
      packageName.includes('\\NullVoid\\package.json'))
  ) {
    return true;
  }

  // Check for TypeScript source files in NullVoid project (more specific)
  if (packageName.includes('/NullVoid/src/') || packageName.includes('\\NullVoid\\src\\')) {
    return true;
  }

  // NullVoid repo structure (only when path suggests this repo)
  const isNullVoidRepo = packageName.includes('NullVoid') || packageName.includes('nullvoid');
  if (
    isNullVoidRepo &&
    (packageName.includes('/ts/src/') ||
      packageName.includes('\\ts\\src\\') ||
      packageName.includes('/js/lib/') ||
      packageName.includes('\\js\\lib\\') ||
      packageName.includes('/ml-model/') ||
      packageName.includes('\\ml-model\\') ||
      packageName.includes('packages/vscode-extension/') ||
      packageName.includes('packages\\vscode-extension\\') ||
      packageName.includes('packages/dashboard/') ||
      packageName.includes('packages\\dashboard\\') ||
      packageName.includes('packages/api/') ||
      packageName.includes('packages\\api\\'))
  ) {
    return true;
  }

  return false;
}

/**
 * Check if a given package name or file path is a test file
 * @param packageName - Package name or file path to check
 * @returns True if this is a test file
 */
export function isTestFile(packageName: string): boolean {
  if (!packageName || typeof packageName !== 'string') {
    return false;
  }

  // Allow malicious test fixtures to be scanned for testing purposes
  if (packageName.includes('fixtures/')) {
    return false;
  }

  return (
    packageName.includes('test/') ||
    packageName.includes('.test.js') ||
    packageName.includes('.spec.js') ||
    packageName.includes('.test.ts') ||
    packageName.includes('.spec.ts') ||
    packageName.includes('__tests__/') ||
    packageName.includes('\\test\\') ||
    packageName.includes('\\__tests__\\') ||
    packageName.startsWith('test-') ||
    packageName.startsWith('test_') ||
    packageName.includes('/test/') ||
    packageName.includes('/tests/') ||
    packageName.includes('\\tests\\')
  );
}

/**
 * Comprehensive detection function that returns detailed results
 * @param packageName - Package name or file path to check
 * @param options - Detection options
 * @returns Detailed detection result
 */
export function detectCodeType(
  packageName: string,
  options: DetectionOptions = {}
): DetectionResult {
  const result: DetectionResult = {
    isNullVoidCode: false,
    isTestFile: false,
    fileName: '',
    confidence: 0,
  };

  if (!packageName || typeof packageName !== 'string') {
    return result;
  }

  // Extract filename
  result.fileName = packageName.split('/').pop() || packageName.split('\\').pop() || packageName;

  // Check if it's NullVoid code
  result.isNullVoidCode = isNullVoidCode(packageName);
  if (result.isNullVoidCode) {
    result.confidence = 100;
    result.matchedPattern = 'NullVoid file or directory';
  }

  // Check if it's a test file
  result.isTestFile = isTestFile(packageName);
  if (result.isTestFile) {
    result.confidence = Math.max(result.confidence, 90);
    result.matchedPattern = result.matchedPattern
      ? `${result.matchedPattern} + test file`
      : 'test file';
  }

  // Apply custom patterns if provided
  if (options.customPatterns) {
    for (const pattern of options.customPatterns) {
      if (packageName.includes(pattern)) {
        result.confidence = Math.max(result.confidence, 80);
        result.matchedPattern = result.matchedPattern
          ? `${result.matchedPattern} + custom pattern`
          : 'custom pattern';
        break;
      }
    }
  }

  // Strict mode: require higher confidence
  if (options.strictMode && result.confidence < 95) {
    result.isNullVoidCode = false;
    result.isTestFile = false;
    result.confidence = 0;
    delete result.matchedPattern;
  }

  return result;
}

/**
 * Check if code should be excluded from analysis
 * @param packageName - Package name or file path to check
 * @param options - Detection options
 * @returns True if code should be excluded
 */
export function shouldExcludeFromAnalysis(
  packageName: string,
  options: DetectionOptions = {}
): boolean {
  const detection = detectCodeType(packageName, options);

  // Exclude NullVoid's own code
  if (detection.isNullVoidCode) {
    return true;
  }

  // Exclude test files if not including them
  if (detection.isTestFile && !options.includeTestFiles) {
    return true;
  }

  return false;
}

/**
 * Get list of NullVoid files for reference
 * @returns Array of NullVoid file names
 */
export function getNullVoidFiles(): string[] {
  return [
    'scan.js',
    'scan.ts',
    'rules.js',
    'rules.ts',
    'benchmarks.js',
    'benchmarks.ts',
    'cache.js',
    'cache.ts',
    'config.js',
    'config.ts',
    'errorHandler.js',
    'errorHandler.ts',
    'logger.js',
    'logger.ts',
    'parallel.js',
    'parallel.ts',
    'rateLimiter.js',
    'rateLimiter.ts',
    'sandbox.js',
    'sandbox.ts',
    'pathSecurity.js',
    'pathSecurity.ts',
    'detection.js',
    'detection.ts',
    'dependencyConfusion.js',
    'dependencyConfusion.ts',
    'nullvoidDetection.js',
    'nullvoidDetection.ts',
    'sarif.js',
    'sarif.ts',
    'secureErrorHandler.js',
    'secureErrorHandler.ts',
    'streaming.js',
    'streaming.ts',
    'validation.js',
    'validation.ts',
    'nullvoid.js',
    'nullvoid.ts',
    'colors.js',
    'colors.ts',
    'generate-badge.js',
    'generate-badge.ts',
    'package.json',
    'README.md',
    'CHANGELOG.md',
    'LICENSE',
    'CONTRIBUTING.md',
    'SECURITY.md',
    'CODE_OF_CONDUCT.md',
    'TYPESCRIPT_MIGRATION_TODO.md',
    'TYPESCRIPT_MIGRATION_GUIDE.md',
  ];
}

/**
 * Get list of test file patterns for reference
 * @returns Array of test file patterns
 */
export function getTestFilePatterns(): string[] {
  return [
    'test/',
    '.test.js',
    '.spec.js',
    '.test.ts',
    '.spec.ts',
    '__tests__/',
    '\\test\\',
    '\\__tests__\\',
    'test-',
    'test_',
    '/test/',
    '/tests/',
    '\\tests\\',
  ];
}

/**
 * NullVoid detection manager class
 */
export class NullVoidDetectionManager {
  private options: DetectionOptions;

  constructor(options: DetectionOptions = {}) {
    this.options = {
      includeTestFiles: false,
      strictMode: false,
      customPatterns: [],
      ...options,
    };
  }

  /**
   * Check if code is NullVoid's own code
   * @param packageName - Package name or file path
   * @returns True if NullVoid code
   */
  isNullVoidCode(packageName: string): boolean {
    return isNullVoidCode(packageName);
  }

  /**
   * Check if code is a test file
   * @param packageName - Package name or file path
   * @returns True if test file
   */
  isTestFile(packageName: string): boolean {
    return isTestFile(packageName);
  }

  /**
   * Get detailed detection result
   * @param packageName - Package name or file path
   * @returns Detailed detection result
   */
  detectCodeType(packageName: string): DetectionResult {
    return detectCodeType(packageName, this.options);
  }

  /**
   * Check if code should be excluded from analysis
   * @param packageName - Package name or file path
   * @returns True if should be excluded
   */
  shouldExcludeFromAnalysis(packageName: string): boolean {
    return shouldExcludeFromAnalysis(packageName, this.options);
  }

  /**
   * Update detection options
   * @param options - New options
   */
  updateOptions(options: Partial<DetectionOptions>): void {
    this.options = { ...this.options, ...options };
  }

  /**
   * Get current options
   * @returns Current options
   */
  getOptions(): DetectionOptions {
    return { ...this.options };
  }

  /**
   * Get NullVoid files list
   * @returns Array of NullVoid file names
   */
  getNullVoidFiles(): string[] {
    return getNullVoidFiles();
  }

  /**
   * Get test file patterns
   * @returns Array of test file patterns
   */
  getTestFilePatterns(): string[] {
    return getTestFilePatterns();
  }
}

/**
 * Create a new NullVoid detection manager
 * @param options - Detection options
 * @returns New detection manager instance
 */
export function createNullVoidDetectionManager(
  options: DetectionOptions = {}
): NullVoidDetectionManager {
  return new NullVoidDetectionManager(options);
}
