import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { jest } from '@jest/globals';
import request from 'supertest';

const repoRoot = path.resolve(__dirname, '../../..');
const fixturesTarget = 'ts/test/fixtures';

describe('API scan lifecycle', () => {
  let dbPath: string;
  let app: import('express').Application;

  beforeAll(async () => {
    dbPath = path.join(os.tmpdir(), `nullvoid-scan-lifecycle-${Date.now()}.db`);
    process.env['NULLVOID_DB_PATH'] = dbPath;
    delete process.env['NULLVOID_API_KEY'];
    process.env['NULLVOID_SCAN_ROOT'] = repoRoot;

    jest.resetModules();

    // eslint-disable-next-line @typescript-eslint/no-var-requires
    app = require('../src/index');
  });

  afterAll(() => {
    for (const suffix of ['', '-shm', '-wal']) {
      const p = `${dbPath}${suffix}`;
      if (fs.existsSync(p)) {
        fs.rmSync(p, { force: true });
      }
    }
  });

  it('runs POST /scan through GET /scan/:id, GET /scans, and GET /report/:id', async () => {
    const postRes = await request(app).post('/scan').send({ target: fixturesTarget });

    expect(postRes.status).toBe(200);
    expect(postRes.body.status).toBe('completed');
    expect(postRes.body.id).toMatch(/^scan-/);
    expect(postRes.body.result?.threats?.length).toBeGreaterThan(0);

    const scanId = postRes.body.id as string;

    const getRes = await request(app).get(`/scan/${scanId}`);
    expect(getRes.status).toBe(200);
    expect(getRes.body.status).toBe('completed');
    expect(getRes.body.result?.threats?.length).toBeGreaterThan(0);

    const listRes = await request(app).get('/scans');
    expect(listRes.status).toBe(200);
    expect(listRes.body.scans.some((s: { id: string }) => s.id === scanId)).toBe(true);

    const reportRes = await request(app)
      .get(`/report/${scanId}`)
      .query({ format: 'markdown' });
    expect(reportRes.status).toBe(200);
    expect(reportRes.headers['content-type']).toMatch(/markdown/);
    expect(reportRes.text.length).toBeGreaterThan(0);
  });

  it('rejects targets outside the scan root', async () => {
    const res = await request(app).post('/scan').send({ target: '../outside' });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain('inside configured scan root');
  });
});
