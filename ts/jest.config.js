const shared = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/test'],
  transform: {
    '^.+\\.ts$': 'ts-jest',
  },
  moduleFileExtensions: ['ts', 'js', 'json'],
  setupFilesAfterEnv: ['<rootDir>/test/setup.ts'],
  verbose: true,
  clearMocks: true,
  restoreMocks: true,
};

module.exports = {
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/test/**/*',
  ],
  projects: [
    {
      ...shared,
      displayName: 'unit',
      testMatch: [
        '<rootDir>/test/unit/**/*.test.ts',
        '<rootDir>/src/test/unit/**/*.test.ts',
      ],
      testTimeout: 15000,
    },
    {
      ...shared,
      displayName: 'integration',
      testMatch: [
        '<rootDir>/test/integration/**/*.test.ts',
        '<rootDir>/test/performance/**/*.test.ts',
        '<rootDir>/src/test/integration/**/*.test.ts',
      ],
      testTimeout: 60000,
    },
  ],
};
