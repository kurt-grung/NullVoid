// Runs the same API test suite against the built Nitro server (see test-nitro/nitroApp.ts).
// Build first: npm run build (builds dist/ and .output/)
const base = require('./jest.config.js');

module.exports = {
  ...base,
  moduleNameMapper: { '^\\.\\./src/index$': '<rootDir>/test-nitro/nitroApp.ts' },
  globalTeardown: '<rootDir>/test-nitro/teardown.js',
  testTimeout: 60_000,
};
