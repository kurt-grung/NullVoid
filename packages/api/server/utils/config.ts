import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

/** Read at server start, same as the Express app (env is fixed per process). */
export const API_KEY = process.env['NULLVOID_API_KEY'] ?? null;
export const SCAN_ROOT = path.resolve(process.env['NULLVOID_SCAN_ROOT'] ?? process.cwd());
export const CORS_ORIGIN = process.env['CORS_ORIGIN'] ?? '*';

/** Platform detection: Railway sets RAILWAY_PROJECT_ID / RAILWAY_ENVIRONMENT_ID */
export const isRailway = !!(
  process.env['RAILWAY_PROJECT_ID'] ?? process.env['RAILWAY_ENVIRONMENT_ID']
);

/** ML commands - only available when API runs locally or on Railway (not on Vercel) */
export const ML_AVAILABLE = process.env['VERCEL'] !== '1';

/**
 * Monorepo root (where ml-model/ and ts/dist live). The Express app derived this from
 * __dirname; a bundled Nitro server lives in .output/, so walk up to the workspace root
 * instead, overridable with NULLVOID_REPO_ROOT.
 */
function findRepoRoot(): string {
  if (process.env['NULLVOID_REPO_ROOT']) return path.resolve(process.env['NULLVOID_REPO_ROOT']);
  let dir = path.dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 8; i++) {
    if (fs.existsSync(path.join(dir, 'turbo.json')) && fs.existsSync(path.join(dir, 'ml-model'))) {
      return dir;
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return process.cwd();
}

export const ROOT = findRepoRoot();

if (CORS_ORIGIN === '*' && process.env['NODE_ENV'] === 'production') {
  console.warn(
    '[nullvoid-api] CORS_ORIGIN is unset; defaulting to wildcard (*). ' +
      'Set CORS_ORIGIN to an explicit origin in production.'
  );
}
