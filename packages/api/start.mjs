#!/usr/bin/env node
/**
 * Starts the NullVoid API. Nitro is the default server; set NULLVOID_API_SERVER=express to
 * run the Express app instead (same routes, same env vars, same port rules).
 *
 *   node packages/api/start.mjs                            # Nitro (.output/server/index.mjs)
 *   NULLVOID_API_SERVER=express node packages/api/start.mjs   # Express (dist/index.js)
 *
 * Both are produced by `npm run api:build`.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const servers = {
  nitro: path.join(here, '.output', 'server', 'index.mjs'),
  express: path.join(here, 'dist', 'index.js'),
};

const choice = (process.env['NULLVOID_API_SERVER'] || 'nitro').trim().toLowerCase();
const entry = servers[choice];
if (!entry) {
  console.error(
    `[nullvoid-api] Unknown NULLVOID_API_SERVER="${choice}". Use "nitro" (default) or "express".`
  );
  process.exit(1);
}
if (!fs.existsSync(entry)) {
  console.error(
    `[nullvoid-api] ${path.relative(process.cwd(), entry)} is missing. Run \`npm run api:build\` first.`
  );
  process.exit(1);
}

console.log(`[nullvoid-api] server: ${choice}`);
if (choice === 'express') {
  process.env['NULLVOID_API_LISTEN'] = '1'; // dist/index.js listens only when asked to
  const { createRequire } = await import('node:module');
  createRequire(import.meta.url)(entry);
} else {
  await import(pathToFileURL(entry).href);
}
