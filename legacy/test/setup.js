// Test setup file

// Set test timeout to 30 seconds for integration tests
jest.setTimeout(30000);

// Mock console methods to reduce noise during tests
global.console = {
  ...console,
  log: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  info: jest.fn()
};

// Set environment variables for testing
process.env.NODE_ENV = 'test';
process.env.NULLVOID_DEBUG = 'false';
