/**
 * Placeholder nullvoid detection module - will be migrated next
 */

export function isNullVoidCode(filePath: string): boolean {
  // Check if file is part of NullVoid's own codebase
  const nullVoidPaths = [
    '/NullVoid/',
    '\\NullVoid\\',
    '/nullvoid/',
    '\\nullvoid\\',
    'bin/nullvoid',
    'lib/',
    'src/',
    'dist/',
    'scan.js',
    'colors.js',
    'nullvoid.js',
    'nullvoid.ts'
  ];
  
  return nullVoidPaths.some(path => filePath.includes(path));
}

export function isTestFile(filePath: string): boolean {
  // Check if file is a test file
  const testPatterns = [
    '.test.js',
    '.spec.js',
    '.test.ts',
    '.spec.ts',
    '/test/',
    '\\test\\',
    '/tests/',
    '\\tests\\'
  ];
  
  return testPatterns.some(pattern => filePath.includes(pattern));
}
