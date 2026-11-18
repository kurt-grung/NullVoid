import { HTTPError, getRouterParam, type H3Event } from 'nitro/h3';
import { API_KEY } from './config';

/** JSON response with a status code (h3 serialises objects as JSON by default). */
export function json<T>(event: H3Event, status: number, body: T): T {
  event.res.status = status;
  return body;
}

/** Marker so server/error.ts sends `body` verbatim, matching Express's res.status(n).json(body). */
export const RESPONSE_BODY = '__nullvoidResponseBody';

/** End the request with an exact JSON body (Express-compatible error shapes like { error }). */
export function fail(status: number, body: Record<string, unknown>): never {
  throw new HTTPError({ status, message: String(body['error'] ?? ''), data: { [RESPONSE_BODY]: body } });
}

export function header(event: H3Event, name: string): string | undefined {
  return event.req.headers.get(name) ?? undefined;
}

export function param(event: H3Event, name: string): string {
  return getRouterParam(event, name, { decode: true }) ?? '';
}

export function query(event: H3Event, name: string): string | undefined {
  return event.url.searchParams.get(name) ?? undefined;
}

const BODY_LIMIT = 256 * 1024;
const BODY_KEY = '__nullvoidBody';

/**
 * Same contract as express.json({ limit: '256kb' }): JSON bodies are parsed, anything else
 * yields {}. Malformed JSON answers 400 and oversized bodies 413 (Express turned both into
 * a generic 500 through its final error handler).
 */
export async function readJson(event: H3Event): Promise<Record<string, any>> {
  const ctx = event.context as Record<string, unknown>;
  if (ctx[BODY_KEY]) return ctx[BODY_KEY] as Record<string, any>;
  let body: Record<string, any> = {};
  const type = event.req.headers.get('content-type') ?? '';
  if (/[/+]json\b/i.test(type)) {
    const text = await event.req.text();
    if (Buffer.byteLength(text) > BODY_LIMIT) {
      throw new HTTPError({ status: 413, message: 'Request body too large' });
    }
    if (text.trim()) {
      try {
        body = JSON.parse(text);
      } catch {
        throw new HTTPError({ status: 400, message: 'Malformed JSON body' });
      }
    }
  }
  ctx[BODY_KEY] = body;
  return body;
}

export function getTenantHeaders(event: H3Event): { organizationId?: string; teamId?: string } {
  return {
    organizationId: header(event, 'x-organization-id'),
    teamId: header(event, 'x-team-id'),
  };
}

/** Same as the Express helper: with API key auth on, X-Organization-Id is mandatory. */
export function requireTenantHeaders(event: H3Event): { organizationId?: string; teamId?: string } {
  const tenant = getTenantHeaders(event);
  if (API_KEY && !tenant.organizationId) {
    fail(400, { error: 'X-Organization-Id is required when API key auth is enabled' });
  }
  return tenant;
}

export function enforceTenantAccess(
  event: H3Event,
  orgId?: string | null,
  teamId?: string | null
): boolean {
  if (!API_KEY) return true;
  const { organizationId: reqOrg, teamId: reqTeam } = getTenantHeaders(event);
  if (!reqOrg || !orgId) return false;
  if (orgId !== reqOrg) return false;
  if (teamId && reqTeam !== teamId) return false;
  return true;
}

export function parseResultJson(rawResultJson: string | null): Record<string, unknown> | undefined {
  if (!rawResultJson) return undefined;
  try {
    return JSON.parse(rawResultJson) as Record<string, unknown>;
  } catch {
    return undefined;
  }
}

export function newId(prefix: string, randLen = 6): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 2 + randLen)}`;
}
