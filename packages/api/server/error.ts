import { defineErrorHandler } from 'nitro';
import { isRailway } from './utils/config';
import { RESPONSE_BODY } from './utils/http';

function jsonResponse(status: number, body: unknown, headers?: Headers): Response {
  const h = new Headers(headers);
  h.set('content-type', 'application/json; charset=utf-8');
  return new Response(JSON.stringify(body), { status, headers: h });
}

export default defineErrorHandler((error, event) => {
  const res = (event as { res?: { headers?: Headers } }).res;
  const headers = res?.headers;
  const data = error.data as Record<string, unknown> | undefined;
  if (data && RESPONSE_BODY in data) {
    return jsonResponse(error.status, data[RESPONSE_BODY], headers);
  }

  // Missing Turso config on Vercel/Railway -> 503 with a setup hint
  const cause = (error.cause ?? error) as { code?: string; message?: string };
  if (cause?.code === 'TURSO_CONFIG_MISSING') {
    return jsonResponse(
      503,
      {
        error: 'Database not configured',
        message: cause.message,
        hint: isRailway
          ? 'Add TURSO_DATABASE_URL and TURSO_AUTH_TOKEN in Railway → Variables.'
          : 'Add TURSO_DATABASE_URL and TURSO_AUTH_TOKEN in Vercel → Settings → Environment Variables.',
      },
      headers
    );
  }

  if (error.status === 404) return jsonResponse(404, { error: 'Not found' }, headers);
  if (error.status >= 400 && error.status < 500) {
    return jsonResponse(error.status, { error: error.message }, headers);
  }

  console.error('[nullvoid-api] Unhandled error:', error.cause ?? error);
  return jsonResponse(
    500,
    {
      error: 'Internal server error',
      message: isRailway
        ? 'Check Railway logs for details.'
        : process.env['VERCEL']
          ? 'Check Vercel logs for details.'
          : 'Check local server logs for details.',
    },
    headers
  );
});
