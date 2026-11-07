const shared = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/test'],
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
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
  ],
  projects: [
    {
      ...shared,
      displayName: 'unit',
      testMatch: [
        '<rootDir>/test/unit/**/*.test.ts',
      ],
    },
    {
      ...shared,
      displayName: 'integration',
      testMatch: [
        '<rootDir>/test/integration/**/*.test.ts',
      ],
    },
    {
      ...shared,
      displayName: 'performance',
      testMatch: ['<rootDir>/test/performance/**/*.test.ts'],
    },
  ],
};
