/**
 * NullVoid Code Detection Utility
 * Centralized logic for identifying NullVoid's own code vs external packages
 */

/**
 * Check if a given package name or file path belongs to NullVoid's own codebase
 * @param {string} packageName - Package name or file path to check
 * @returns {boolean} True if this is NullVoid's own code
 */
function isNullVoidCode(packageName) {
  if (!packageName || typeof packageName !== 'string') {
    return false;
  }

  // Extract filename for more precise matching
  const fileName = packageName.split('/').pop() || packageName.split('\\').pop();
  
  // Check for specific NullVoid project files
  const nullVoidFiles = [
    'scan.js',
    'rules.js', 
    'benchmarks.js',
    'cache.js',
    'config.js',
    'errorHandler.js',
    'logger.js',
    'parallel.js',
    'rateLimiter.js',
    'sandbox.js',
    'pathSecurity.js',
    'secureErrorHandler.js',
    'streaming.js',
    'validation.js',
    'nullvoid.js',
    'colors.js',
    'package.json',
    'README.md',
    'CHANGELOG.md',
    'LICENSE',
    'CONTRIBUTING.md',
    'SECURITY.md',
    'CODE_OF_CONDUCT.md'
  ];

  // Check if filename matches NullVoid files
  if (nullVoidFiles.includes(fileName)) {
    return true;
  }

  // Check for NullVoid directory structure (more specific)
  if (packageName.includes('/NullVoid/') && (
    packageName.includes('/NullVoid/lib/') ||
    packageName.includes('/NullVoid/bin/') ||
    packageName.includes('/NullVoid/scan.js') ||
    packageName.includes('/NullVoid/package.json')
  )) {
    return true;
  }

  if (packageName.includes('\\NullVoid\\') && (
    packageName.includes('\\NullVoid\\lib\\') ||
    packageName.includes('\\NullVoid\\bin\\') ||
    packageName.includes('\\NullVoid\\scan.js') ||
    packageName.includes('\\NullVoid\\package.json')
  )) {
    return true;
  }

  return false;
}

/**
 * Check if a given package name or file path is a test file
 * @param {string} packageName - Package name or file path to check
 * @returns {boolean} True if this is a test file
 */
function isTestFile(packageName) {
  if (!packageName || typeof packageName !== 'string') {
    return false;
  }

  return (
    packageName.includes('test/') ||
    packageName.includes('.test.js') ||
    packageName.includes('.spec.js') ||
    packageName.includes('__tests__/') ||
    packageName.includes('\\test\\') ||
    packageName.includes('.test.ts') ||
    packageName.includes('.spec.ts') ||
    packageName.startsWith('test-') ||
    packageName.startsWith('test_')
  );
}

module.exports = {
  isNullVoidCode,
  isTestFile
};
