import type { H3Event } from 'nitro/h3';
import { fail, header } from './http';

/**
 * Fixed-window, in-memory limiter matching the Express app's express-rate-limit setup:
 * 60s window, keyed by client IP, standard RateLimit-* headers, 429 with a JSON message.
 * Like express-rate-limit's MemoryStore it is per process (per instance on serverless).
 */
interface Window {
  count: number;
  resetAt: number;
}

/**
 * Client IP with Express's `trust proxy: 1` semantics: behind exactly one proxy the real
 * client is the right-most X-Forwarded-For entry; otherwise the socket address.
 */
export function clientIp(event: H3Event): string {
  const xff = header(event, 'x-forwarded-for');
  if (xff) {
    const parts = xff.split(',').map((p) => p.trim()).filter(Boolean);
    if (parts.length) return parts[parts.length - 1]!;
  }
  return (event.req as { ip?: string }).ip ?? 'unknown';
}

export function createRateLimit(opts: { windowMs: number; max: number; message: string }) {
  const hits = new Map<string, Window>();
  return function rateLimit(event: H3Event): void {
    const now = Date.now();
    const key = clientIp(event);
    let w = hits.get(key);
    if (!w || w.resetAt <= now) {
      w = { count: 0, resetAt: now + opts.windowMs };
      hits.set(key, w);
      if (hits.size > 10_000) {
        for (const [k, v] of hits) if (v.resetAt <= now) hits.delete(k);
      }
    }
    w.count++;
    const remaining = Math.max(0, opts.max - w.count);
    const reset = Math.max(0, Math.ceil((w.resetAt - now) / 1000));
    const h = event.res.headers;
    h.set('RateLimit-Policy', `${opts.max};w=${Math.round(opts.windowMs / 1000)}`);
    h.set('RateLimit-Limit', String(opts.max));
    h.set('RateLimit-Remaining', String(remaining));
    h.set('RateLimit-Reset', String(reset));
    if (w.count > opts.max) {
      h.set('Retry-After', String(reset));
      fail(429, { error: opts.message });
    }
  };
}

export const scanRateLimit = createRateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: 'Too many requests — please wait before submitting another scan.',
});

export const mlRateLimit = createRateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: 'Too many ML requests — please slow down.',
});
