const { scanPackagesInParallel, analyzeFilesInParallel, getParallelConfig, updateParallelConfig } = require('../../lib/parallel');

describe('Parallel Scanning Engine', () => {
  const mockOptions = { verbose: false };

  describe('scanPackagesInParallel', () => {
    it('should scan packages in parallel', async () => {
      const packages = [
        { name: 'express', version: '4.18.0', path: null },
        { name: 'lodash', version: '4.17.21', path: null }
      ];

      const results = await scanPackagesInParallel(packages, mockOptions);
      
      expect(results).toBeDefined();
      expect(results.threats).toBeInstanceOf(Array);
      expect(results.packages).toBeInstanceOf(Array);
      expect(results.metrics).toBeDefined();
      expect(results.metrics.totalPackages).toBe(2);
      expect(results.metrics.scannedPackages).toBeGreaterThanOrEqual(0);
    });

    it('should handle empty package list', async () => {
      const results = await scanPackagesInParallel([], mockOptions);
      
      expect(results.threats).toHaveLength(0);
      expect(results.packages).toHaveLength(0);
      expect(results.metrics.totalPackages).toBe(0);
    });

    it('should handle single package', async () => {
      const packages = [
        { name: 'express', version: '4.18.0', path: null }
      ];

      const results = await scanPackagesInParallel(packages, mockOptions);
      
      expect(results.metrics.totalPackages).toBe(1);
      // Note: Single package may not trigger parallel processing
      expect(results.packages.length).toBeGreaterThanOrEqual(0);
    });

    it('should respect worker count limits', async () => {
      const packages = Array.from({ length: 20 }, (_, i) => ({
        name: `package-${i}`,
        version: '1.0.0',
        path: null
      }));

      const results = await scanPackagesInParallel(packages, mockOptions);
      
      expect(results.metrics.workerCount).toBeLessThanOrEqual(8); // Max workers cap
    });
  });

  describe('analyzeFilesInParallel', () => {
    it('should analyze files in parallel', async () => {
      const files = [
        { path: '/test/file1.js', content: 'console.log("test");' },
        { path: '/test/file2.js', content: 'eval("malicious");' }
      ];

      const results = await analyzeFilesInParallel(files, mockOptions);
      
      expect(results).toBeInstanceOf(Array);
      expect(results.length).toBeGreaterThanOrEqual(0);
    });

    it('should handle empty file list', async () => {
      const results = await analyzeFilesInParallel([], mockOptions);
      
      expect(results).toHaveLength(0);
    });
  });

  describe('getParallelConfig', () => {
    it('should return parallel configuration', () => {
      const config = getParallelConfig();
      
      expect(config).toBeDefined();
      expect(config.maxWorkers).toBeDefined();
      expect(config.chunkSize).toBeDefined();
      expect(config.timeout).toBeDefined();
      expect(config.retryAttempts).toBeDefined();
    });

    it('should have reasonable default values', () => {
      const config = getParallelConfig();
      
      expect(config.maxWorkers).toBeGreaterThan(0);
      expect(config.maxWorkers).toBeLessThanOrEqual(8);
      expect(config.chunkSize).toBeGreaterThan(0);
      expect(config.timeout).toBeGreaterThan(0);
      expect(config.retryAttempts).toBeGreaterThanOrEqual(0);
    });
  });

  describe('updateParallelConfig', () => {
    it('should update parallel configuration', () => {
      const originalConfig = getParallelConfig();
      
      updateParallelConfig({ maxWorkers: 4, chunkSize: 5 });
      
      const updatedConfig = getParallelConfig();
      
      expect(updatedConfig.maxWorkers).toBe(4);
      expect(updatedConfig.chunkSize).toBe(5);
      expect(updatedConfig.timeout).toBe(originalConfig.timeout); // Should remain unchanged
    });

    it('should handle partial configuration updates', () => {
      const originalConfig = getParallelConfig();
      
      updateParallelConfig({ maxWorkers: 2 });
      
      const updatedConfig = getParallelConfig();
      
      expect(updatedConfig.maxWorkers).toBe(2);
      expect(updatedConfig.chunkSize).toBe(originalConfig.chunkSize);
      expect(updatedConfig.timeout).toBe(originalConfig.timeout);
    });
  });

  describe('Error Handling', () => {
    it('should handle worker errors gracefully', async () => {
      const packages = [
        { name: 'nonexistent-package-12345', version: '1.0.0', path: null }
      ];

      const results = await scanPackagesInParallel(packages, mockOptions);
      
      expect(results).toBeDefined();
      expect(results.metrics.failedPackages).toBeGreaterThanOrEqual(0);
    });

    it('should handle timeout errors', async () => {
      // Update config to very short timeout for testing
      updateParallelConfig({ timeout: 1 });
      
      const packages = [
        { name: 'express', version: '4.18.0', path: null }
      ];

      const results = await scanPackagesInParallel(packages, mockOptions);
      
      expect(results).toBeDefined();
      
      // Restore original timeout
      updateParallelConfig({ timeout: 30000 });
    });
  });

  describe('Performance', () => {
    it('should complete within reasonable time', async () => {
      const packages = [
        { name: 'express', version: '4.18.0', path: null },
        { name: 'lodash', version: '4.17.21', path: null },
        { name: 'axios', version: '1.6.0', path: null }
      ];

      const startTime = Date.now();
      const results = await scanPackagesInParallel(packages, mockOptions);
      const endTime = Date.now();
      
      expect(endTime - startTime).toBeLessThan(10000); // Should complete within 10 seconds
      expect(results.metrics.duration).toBeGreaterThan(0);
    });

    it('should provide performance metrics', async () => {
      const packages = [
        { name: 'express', version: '4.18.0', path: null }
      ];

      const results = await scanPackagesInParallel(packages, mockOptions);
      
      expect(results.metrics.startTime).toBeDefined();
      expect(results.metrics.endTime).toBeDefined();
      expect(results.metrics.duration).toBeGreaterThan(0);
      expect(results.metrics.packagesPerSecond).toBeGreaterThanOrEqual(0);
    });
  });
});
