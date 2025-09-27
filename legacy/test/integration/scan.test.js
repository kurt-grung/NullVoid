const { describe, it, expect, beforeEach, afterEach } = require('@jest/globals');
const { scan } = require('../../scan');
const fs = require('fs');
const path = require('path');

// Mock npm registry responses
jest.mock('https', () => ({
  get: jest.fn()
}));

describe('Integration Tests', () => {
  let tempDir;
  let packageJsonPath;

  beforeEach(() => {
    // Create temporary directory for testing
    tempDir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'nullvoid-test-'));
    packageJsonPath = path.join(tempDir, 'package.json');
  });

  afterEach(() => {
    // Clean up temporary directory
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  describe('Package.json Scanning', () => {
    it('should scan package.json with dependencies', async () => {
      const packageJson = {
        name: 'test-package',
        version: '1.0.0',
        dependencies: {
          'express': '^4.18.0',
          'lodash': '^4.17.21'
        }
      };

      fs.writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, 2));

      // Mock the current working directory
      const originalCwd = process.cwd();
      process.chdir(tempDir);

      try {
        const results = await scan();
        
        expect(results).toHaveProperty('threats');
        expect(results).toHaveProperty('packagesScanned');
        expect(results).toHaveProperty('dependencyTree');
        expect(results).toHaveProperty('performance');
        expect(Array.isArray(results.threats)).toBe(true);
        expect(typeof results.packagesScanned).toBe('number');
      } finally {
        process.chdir(originalCwd);
      }
    });

    it('should handle missing package.json gracefully', async () => {
      // Don't create package.json file
      
      const originalCwd = process.cwd();
      process.chdir(tempDir);

      try {
        const results = await scan();
        
        expect(results).toHaveProperty('threats');
        expect(results).toHaveProperty('filesScanned');
        expect(results).toHaveProperty('directoryStructure');
        expect(Array.isArray(results.threats)).toBe(true);
      } finally {
        process.chdir(originalCwd);
      }
    });

    it('should handle invalid package.json', async () => {
      fs.writeFileSync(packageJsonPath, 'invalid json content');

      const originalCwd = process.cwd();
      process.chdir(tempDir);

      try {
        // With new behavior, scan() scans directory instead of package.json
        // So it should not throw an error, just scan the directory
        const result = await scan();
        expect(result).toBeDefined();
        expect(result.threats).toBeDefined();
      } finally {
        process.chdir(originalCwd);
      }
    });
  });

  describe('Directory Scanning', () => {
    it('should scan JavaScript files in directory', async () => {
      // Create test JavaScript files
      const jsFile = path.join(tempDir, 'test.js');
      const jsxFile = path.join(tempDir, 'test.jsx');
      
      fs.writeFileSync(jsFile, 'function hello() { return "world"; }');
      fs.writeFileSync(jsxFile, 'const Component = () => <div>Hello</div>;');

      const originalCwd = process.cwd();
      process.chdir(tempDir);

      try {
        const results = await scan();
        
        expect(results).toHaveProperty('threats');
        expect(results).toHaveProperty('filesScanned');
        expect(results.filesScanned).toBeGreaterThan(0);
        expect(Array.isArray(results.threats)).toBe(true);
      } finally {
        process.chdir(originalCwd);
      }
    });

    it('should handle empty directory', async () => {
      const originalCwd = process.cwd();
      process.chdir(tempDir);

      try {
        const results = await scan();
        
        expect(results).toHaveProperty('threats');
        expect(results).toHaveProperty('filesScanned');
        expect(results.filesScanned).toBe(0);
        expect(Array.isArray(results.threats)).toBe(true);
      } finally {
        process.chdir(originalCwd);
      }
    });
  });

  describe('Performance Monitoring', () => {
    it('should include performance metrics in results', async () => {
      const packageJson = {
        name: 'test-package',
        version: '1.0.0',
        dependencies: {
          'express': '^4.18.0'
        }
      };

      fs.writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, 2));

      const originalCwd = process.cwd();
      process.chdir(tempDir);

      try {
        const results = await scan();
        
        expect(results).toHaveProperty('performance');
        expect(results.performance).toHaveProperty('packagesScanned');
        expect(results.performance).toHaveProperty('cacheHits');
        expect(results.performance).toHaveProperty('cacheMisses');
        expect(results.performance).toHaveProperty('networkRequests');
        expect(results.performance).toHaveProperty('errors');
        expect(results.performance).toHaveProperty('packagesPerSecond');
      } finally {
        process.chdir(originalCwd);
      }
    });
  });
});
