import { defineMiddleware } from 'nitro';
import { requireAuth } from '../utils/auth';

// Global API key check (Express ran authMiddleware for everything except the API docs).
export default defineMiddleware((event) => {
  const p = event.url.pathname;
  if (p === '/api-docs.json' || p === '/api-docs' || p.startsWith('/api-docs/')) return;
  requireAuth(event);
});
