import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import request from 'supertest';

/**
 * Rate limits (10 scans / 20 ML commands per minute per client). Runs against Express and,
 * through jest.nitro.config.js, against the Nitro build, so both must agree on counting,
 * headers and the 429 body.
 */
let dbPath: string;
let app: any;
const savedEnv = { ...process.env };

beforeAll(() => {
  dbPath = path.join(os.tmpdir(), `nullvoid-api-ratelimit-${Date.now()}.db`);
  process.env['NULLVOID_DB_PATH'] = dbPath;
  process.env['NULLVOID_API_KEY'] = '';
  process.env['NULLVOID_SCAN_ROOT'] = path.join(os.tmpdir(), 'nullvoid-api-scan-root');
  // ML commands answer 503 without running anything; the limiter still counts them first.
  process.env['VERCEL'] = '1';
  process.env['TURSO_DATABASE_URL'] = `file:${dbPath}`;
  process.env['TURSO_AUTH_TOKEN'] = 'local';
  fs.mkdirSync(process.env['NULLVOID_SCAN_ROOT'], { recursive: true });
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  app = require('../src/index');
});

afterAll(() => {
  process.env = savedEnv;
  for (const suffix of ['', '-shm', '-wal']) fs.rmSync(`${dbPath}${suffix}`, { force: true });
});

describe('rate limits', () => {
  it('allows 10 scan requests a minute, then answers 429', async () => {
    for (let i = 0; i < 10; i++) {
      // invalid target: rejected before any scan runs, but still counted
      const res = await request(app).post('/scan').send({ target: 'evil;curl' });
      expect(res.status).toBe(400);
      expect(res.headers['ratelimit-limit']).toBe('10');
      expect(res.headers['ratelimit-remaining']).toBe(String(9 - i));
    }
    const limited = await request(app).post('/scan').send({ target: 'evil;curl' });
    expect(limited.status).toBe(429);
    expect(limited.body).toEqual({
      error: 'Too many requests — please wait before submitting another scan.',
    });
    expect(limited.headers['ratelimit-remaining']).toBe('0');
    expect(Number(limited.headers['retry-after'])).toBeGreaterThan(0);
  });

  it('does not rate limit read endpoints', async () => {
    for (let i = 0; i < 15; i++) {
      const res = await request(app).get('/health');
      expect(res.status).toBe(200);
      expect(res.headers['ratelimit-limit']).toBeUndefined();
    }
  });

  it('allows 20 ML commands a minute across ML routes, then answers 429', async () => {
    const routes = ['/ml/export', '/ml/train', '/ml/export-behavioral', '/ml/train-behavioral'];
    for (let i = 0; i < 20; i++) {
      const res = await request(app).post(routes[i % routes.length]!);
      expect(res.status).toBe(503);
      expect(res.headers['ratelimit-limit']).toBe('20');
    }
    const limited = await request(app).post('/ml/train');
    expect(limited.status).toBe(429);
    expect(limited.body).toEqual({ error: 'Too many ML requests — please slow down.' });
    expect(limited.headers['retry-after']).toBeDefined();
  });
});
