// Jest setup file for TypeScript tests
import { jest } from '@jest/globals';
import { getResourceMonitor } from '../src/lib/parallel/resourceMonitor';
import { getConnectionPool } from '../src/lib/network/connectionPool';

// Global test setup
beforeEach(() => {
  // Clear all mocks before each test
  jest.clearAllMocks();
});

// Global test timeout
jest.setTimeout(10000);

// Cleanup after all tests
afterAll(async () => {
  // Stop resource monitoring
  try {
    const resourceMonitor = getResourceMonitor();
    resourceMonitor.stopMonitoring();
  } catch (e) {
    // Ignore errors
  }
  
  // Close connection pools
  try {
    const connectionPool = getConnectionPool();
    connectionPool.close();
  } catch (e) {
    // Ignore errors
  }
  
  // Give time for any pending async operations to complete
  await new Promise(resolve => setTimeout(resolve, 100));
});
