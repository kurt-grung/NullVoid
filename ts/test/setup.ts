// Jest setup file for TypeScript tests
import { jest } from '@jest/globals';
import { getConnectionPool } from '../src/lib/network/connectionPool';

// Global test setup
beforeEach(() => {
  // Clear all mocks before each test
  jest.clearAllMocks();
});

// Cleanup after all tests
afterAll(async () => {
  // Close connection pools
  try {
    const connectionPool = getConnectionPool();
    connectionPool.close();
  } catch (e) {
    // Ignore errors
  }

  // Give time for any pending async operations to complete
  await new Promise((resolve) => setTimeout(resolve, 100));
});
