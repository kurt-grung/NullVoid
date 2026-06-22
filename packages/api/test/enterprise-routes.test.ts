import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { jest } from '@jest/globals';
import request from 'supertest';

describe('enterprise routes', () => {
  let app: ReturnType<typeof require>;

  beforeAll(async () => {
    const dbPath = path.join(os.tmpdir(), `nullvoid-api-enterprise-${Date.now()}.db`);
    process.env['NULLVOID_DB_PATH'] = dbPath;
    delete process.env['NULLVOID_API_KEY'];
    process.env['NULLVOID_SCAN_ROOT'] = path.join(os.tmpdir(), 'nullvoid-api-enterprise-root');
    fs.mkdirSync(process.env['NULLVOID_SCAN_ROOT'], { recursive: true });
    jest.resetModules();
    app = require('../src/index');
  });

  it('GET /graphql returns planned schema info', async () => {
    const res = await request(app).get('/graphql');
    expect(res.status).toBe(200);
    expect(res.body.plannedQueries).toContain('scans');
  });

  it('GET /schedules returns list', async () => {
    const res = await request(app).get('/schedules');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.schedules)).toBe(true);
  });
});
