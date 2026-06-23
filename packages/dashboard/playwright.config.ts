import { defineConfig, devices } from '@playwright/test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const e2eDb = process.env['NULLVOID_DB_PATH'] ?? '/tmp/nullvoid-e2e-playwright.db';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  forbidOnly: !!process.env['CI'],
  retries: process.env['CI'] ? 2 : 0,
  workers: 1,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: 'http://localhost:5174',
    trace: 'on-first-retry',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: [
    {
      command: 'node packages/api/dist/index.js',
      cwd: repoRoot,
      url: 'http://localhost:3001/health',
      reuseExistingServer: !process.env['CI'],
      env: {
        ...process.env,
        NULLVOID_DB_PATH: e2eDb,
        NULLVOID_SCAN_ROOT: repoRoot,
        NULLVOID_API_KEY: '',
      },
    },
    {
      command: 'npm run dev -w dashboard',
      cwd: repoRoot,
      url: 'http://localhost:5174',
      reuseExistingServer: !process.env['CI'],
      env: {
        ...process.env,
        API_PROXY_TARGET: 'http://localhost:3001',
      },
    },
  ],
});
