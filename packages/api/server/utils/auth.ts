import type { H3Event } from 'nitro/h3';
import { API_KEY } from './config';
import { fail, header } from './http';

/** Same check as the Express authMiddleware/requireAuth: X-API-Key must match when set. */
export function requireAuth(event: H3Event): void {
  if (!API_KEY) return;
  const key = header(event, 'x-api-key');
  if (!key || key !== API_KEY) {
    fail(401, { error: 'Invalid or missing X-API-Key' });
  }
}
