import { createRequire } from 'node:module';
import * as path from 'node:path';
import { defineConfig } from 'nitro';

const swaggerDist = path.dirname(
  createRequire(import.meta.url).resolve('swagger-ui-dist/package.json')
);

/**
 * Nitro build of the NullVoid API (runs side by side with the Express app in src/index.ts).
 * Business logic is shared: server/utils/core.ts imports it from src/, so the output in
 * .output/ is self-contained (no dist/ or repo checkout needed at runtime).
 */
export default defineConfig({
  serverDir: './server',
  compatibilityDate: '2026-11-01',
  errorHandler: './server/error.ts',
  // Swagger UI files, bundled so /api-docs works without node_modules at runtime
  serverAssets: [
    {
      baseName: 'swagger',
      dir: swaggerDist,
      pattern: '{swagger-ui.css,swagger-ui-bundle.js,swagger-ui-standalone-preset.js,favicon-32x32.png,favicon-16x16.png}',
    },
  ],
});
