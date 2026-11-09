const shared = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/test'],
  modulePathIgnorePatterns: ['<rootDir>/benchmark/'],
  transform: {
    '^.+\\.ts$': 'ts-jest',
  },
  moduleFileExtensions: ['ts', 'js', 'json'],
  setupFilesAfterEnv: ['<rootDir>/test/setup.ts'],
  clearMocks: true,
  restoreMocks: true,
};

module.exports = {
  // Jest 30 rejects testTimeout inside `projects`; one global value instead.
  testTimeout: 60000,
  collectCoverageFrom: ['src/**/*.ts', '!src/**/*.d.ts'],
  // Floor = measured value at the time it was set (2026-11: 60.0 / 47.7 / 55.1 / 61.1),
  // rounded down. Raise it with each release; never lower it to make a PR pass.
  coverageThreshold: {
    global: {
      statements: 59,
      branches: 46,
      functions: 54,
      lines: 60,
    },
  },
  projects: [
    {
      ...shared,
      displayName: 'unit',
      testMatch: ['<rootDir>/test/unit/**/*.test.ts'],
    },
    {
      ...shared,
      // Runs the built binary (dist/); skipped when not built.
      displayName: 'cli',
      testMatch: ['<rootDir>/test/cli/**/*.test.ts'],
    },
    {
      ...shared,
      displayName: 'integration',
      testMatch: ['<rootDir>/test/integration/**/*.test.ts'],
    },
    {
      ...shared,
      displayName: 'performance',
      testMatch: ['<rootDir>/test/performance/**/*.test.ts'],
    },
  ],
};
