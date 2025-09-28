// Jest setup file for TypeScript tests
import { jest } from '@jest/globals';

// Global test setup
beforeEach(() => {
  // Clear all mocks before each test
  jest.clearAllMocks();
});

// Global test timeout
jest.setTimeout(10000);
