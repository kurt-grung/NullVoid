import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { jest } from '@jest/globals';
import request from 'supertest';

type DbModule = {
  insertScan: (row: {
    id: string;
    organizationId?: string;
    teamId?: string;
    target: string;
    status: string;
  }) => Promise<void>;
};

describe('GET /scans in no-auth mode', () => {
  let dbPath: string;
  let app: any;
  let db: DbModule;

  beforeAll(async () => {
    dbPath = path.join(os.tmpdir(), `nullvoid-api-noauth-${Date.now()}.db`);
    process.env['NULLVOID_DB_PATH'] = dbPath;
    delete process.env['NULLVOID_API_KEY'];
    process.env['NULLVOID_SCAN_ROOT'] = path.join(os.tmpdir(), 'nullvoid-api-noauth-root');
    fs.mkdirSync(process.env['NULLVOID_SCAN_ROOT'], { recursive: true });

    jest.resetModules();

    // eslint-disable-next-line @typescript-eslint/no-var-requires
    app = require('../src/index');
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    db = require('../src/db');
  });

  afterAll(() => {
    for (const suffix of ['', '-shm', '-wal']) {
      const p = `${dbPath}${suffix}`;
      if (fs.existsSync(p)) {
        fs.rmSync(p, { force: true });
      }
    }
  });

  it('returns scans without tenant headers when API key is not configured', async () => {
    await db.insertScan({
      id: `scan-${Date.now()}-public`,
      target: '/tmp/noauth',
      status: 'completed',
    });

    const res = await request(app).get('/scans');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.scans)).toBe(true);
    expect(res.body.scans.length).toBeGreaterThan(0);
  });
});
