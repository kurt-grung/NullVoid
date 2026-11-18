import { defineHandler } from 'nitro';
import { useStorage } from 'nitro/storage';
import * as path from 'node:path';
import { fail, param } from '../../utils/http';
import { INITIALIZER, indexHtml } from '../../utils/swagger';

/**
 * Swagger UI at /api-docs, served from swagger-ui-dist files bundled as server assets
 * (see nitro.config.ts). The page loads the spec from /api-docs.json.
 */
const TYPES: Record<string, string> = {
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.png': 'image/png',
};

export default defineHandler(async (event) => {
  const file = param(event, 'path') || 'index.html';
  if (file === 'index.html') {
    event.res.headers.set('content-type', 'text/html; charset=utf-8');
    return indexHtml();
  }
  if (file === 'swagger-initializer.js') {
    event.res.headers.set('content-type', TYPES['.js']!);
    return INITIALIZER;
  }
  const ext = path.extname(file);
  if (path.basename(file) !== file || !TYPES[ext]) fail(404, { error: 'Not found' });
  const data = await useStorage('assets:swagger').getItemRaw(file);
  if (!data) fail(404, { error: 'Not found' });
  event.res.headers.set('content-type', TYPES[ext]!);
  event.res.headers.set('cache-control', 'public, max-age=86400');
  return data;
});
