import { defineMiddleware } from 'nitro';
import { CORS_ORIGIN } from '../utils/config';

// CORS: allow the dashboard (or other origins) to call the API; preflights end here.
export default defineMiddleware((event) => {
  const h = event.res.headers;
  h.set('Access-Control-Allow-Origin', CORS_ORIGIN);
  h.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  h.set(
    'Access-Control-Allow-Headers',
    'Content-Type, X-API-Key, X-Organization-Id, X-Team-Id, X-NullVoid-Role'
  );
  if (event.req.method === 'OPTIONS') {
    event.res.status = 204;
    return '';
  }
  return undefined;
});
