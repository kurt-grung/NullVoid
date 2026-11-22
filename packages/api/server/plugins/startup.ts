import { definePlugin } from 'nitro';
import { jobs } from '../utils/core';

/**
 * What Express did around app.listen(). Plugins run before the Nitro server reads its port,
 * so the Express port rules apply: PORT, then NULLVOID_API_PORT, then 3001 (Nitro alone
 * would default to 3000). NITRO_PORT still wins when set.
 */
export default definePlugin(() => {
  if (process.env['VERCEL'] === '1') return; // serverless: no port, no schedule runner
  if (!process.env['NITRO_PORT'] && !process.env['PORT']) {
    process.env['PORT'] = process.env['NULLVOID_API_PORT'] ?? '3001';
  }
  console.log(`NullVoid API listening on port ${process.env['NITRO_PORT'] ?? process.env['PORT']}`);
  jobs.startScheduleRunner();
});
