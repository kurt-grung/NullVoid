import { definePlugin } from 'nitro';
import type { H3Event } from 'nitro/h3';

/**
 * Behind the Vercel rewrite requests arrive as /api/scan etc.; serve them on the bare paths
 * (Express stripped the prefix in a middleware). Nitro matches routes before global
 * middleware runs, so this has to happen in the `request` hook.
 */
export default definePlugin((nitroApp) => {
  nitroApp.hooks.hook('request', (httpEvent) => {
    // The hook receives the full H3 event at runtime; its declared type is the narrower HTTPEvent.
    const event = httpEvent as H3Event;
    const { pathname } = event.url;
    (event.context as Record<string, unknown>)['originalPathname'] = pathname;
    if (pathname === '/api' || pathname.startsWith('/api/')) {
      event.url.pathname = pathname.slice(4) || '/';
    }
  });
});
