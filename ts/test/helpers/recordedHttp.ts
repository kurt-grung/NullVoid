/**
 * Recorded HTTP responses for provider tests.
 *
 * Every IoC provider goes through providerFetch → fetchWithTimeout, so a test
 * mocks that one module and serves bodies from test/fixtures/http/*.json:
 *
 *   jest.mock('../../src/lib/providers/fetchWithTimeout');
 *   const http = useRecordedHttp();
 *   http.on(/registry\.npmjs\.org/, 'npm-advisories-lodash');
 *
 * A fixture file is { "status": 200, "body": {...} } (status optional). An
 * unmatched URL fails the test instead of reaching the network.
 */

import * as fs from 'fs';
import * as path from 'path';
import { fetchWithTimeout } from '../../src/lib/providers/fetchWithTimeout';

export const FIXTURE_DIR = path.resolve(__dirname, '../fixtures/http');

interface Recorded {
  status?: number;
  statusText?: string;
  body?: unknown;
}

export interface RecordedCall {
  url: string;
  method: string;
  body?: string | undefined;
}

function readFixture(name: string): Recorded {
  return JSON.parse(fs.readFileSync(path.join(FIXTURE_DIR, `${name}.json`), 'utf8')) as Recorded;
}

export function fakeResponse(rec: Recorded): unknown {
  const status = rec.status ?? 200;
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: rec.statusText ?? (status === 200 ? 'OK' : `HTTP ${status}`),
    headers: { get: () => null },
    json: async () => rec.body,
    text: async () => (typeof rec.body === 'string' ? rec.body : JSON.stringify(rec.body)),
  };
}

export function useRecordedHttp(): {
  on: (match: RegExp | string, fixtureOrRecord: string | Recorded) => void;
  calls: RecordedCall[];
  reset: () => void;
} {
  const routes: Array<{ match: RegExp | string; rec: Recorded }> = [];
  const calls: RecordedCall[] = [];
  const mocked = fetchWithTimeout as unknown as jest.Mock;
  if (typeof mocked.mockImplementation !== 'function') {
    throw new Error(
      "call jest.mock('../../src/lib/providers/fetchWithTimeout') before useRecordedHttp()"
    );
  }

  mocked.mockImplementation(async (url: string, options?: { method?: string; body?: string }) => {
    calls.push({ url, method: options?.method ?? 'GET', body: options?.body });
    const route = routes.find((r) =>
      typeof r.match === 'string' ? url.includes(r.match) : r.match.test(url)
    );
    if (!route) throw new Error(`recordedHttp: no fixture registered for ${url}`);
    return fakeResponse(route.rec);
  });

  return {
    on(match, fixtureOrRecord) {
      routes.push({
        match,
        rec: typeof fixtureOrRecord === 'string' ? readFixture(fixtureOrRecord) : fixtureOrRecord,
      });
    },
    calls,
    reset() {
      routes.length = 0;
      calls.length = 0;
    },
  };
}
