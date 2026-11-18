import { defineHandler } from 'nitro';
import { isRailway } from '../utils/config';
import { query } from '../utils/http';

/** GET /health - optional ?platform=1 for platform info */
export default defineHandler((event) => {
  const body: { ok: boolean; platform?: string } = { ok: true };
  if (query(event, 'platform') === '1') {
    body.platform = isRailway ? 'railway' : process.env['VERCEL'] === '1' ? 'vercel' : 'local';
  }
  return body;
});
