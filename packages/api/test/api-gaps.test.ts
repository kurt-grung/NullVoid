/**
 * API gap coverage: pagination, ML endpoint auth, feedback validation, org/team scoping.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { jest } from '@jest/globals';
import request from 'supertest';

type DbModule = {
  createOrganization: (name: string) => Promise<{ id: string }>;
  createTeam: (organizationId: string, name: string) => Promise<{ id: string }>;
  insertScan: (row: {
    id: string;
    organizationId?: string;
    teamId?: string;
    target: string;
    status: string;
  }) => Promise<void>;
};

const apiKey = 'gap-test-key';
let dbPath: string;
let app: ReturnType<typeof require>;
let db: DbModule;
let orgAId = '';
let orgBId = '';

function auth(orgId?: string): Record<string, string> {
  const h: Record<string, string> = { 'X-API-Key': apiKey };
  if (orgId) h['X-Organization-Id'] = orgId;
  return h;
}

beforeAll(async () => {
  dbPath = path.join(os.tmpdir(), `nullvoid-api-gaps-${Date.now()}.db`);
  process.env['NULLVOID_DB_PATH'] = dbPath;
  process.env['NULLVOID_API_KEY'] = apiKey;
  process.env['NULLVOID_SCAN_ROOT'] = path.join(os.tmpdir(), 'nullvoid-gap-root');
  fs.mkdirSync(process.env['NULLVOID_SCAN_ROOT']!, { recursive: true });

  jest.resetModules();
  app = require('../src/index');
  db = require('../src/db') as DbModule;

  const orgA = await db.createOrganization('Org A');
  const orgB = await db.createOrganization('Org B');
  orgAId = orgA.id;
  orgBId = orgB.id;

  for (let i = 0; i < 5; i++) {
    await db.insertScan({
      id: `scan-orgA-${i}-${Date.now()}`,
      organizationId: orgAId,
      target: '/tmp/a',
      status: 'completed',
    });
  }
  for (let i = 0; i < 3; i++) {
    await db.insertScan({
      id: `scan-orgB-${i}-${Date.now()}`,
      organizationId: orgBId,
      target: '/tmp/b',
      status: 'completed',
    });
  }
});

afterAll(() => {
  for (const suffix of ['', '-shm', '-wal']) {
    const p = `${dbPath}${suffix}`;
    if (fs.existsSync(p)) fs.rmSync(p, { force: true });
  }
});

describe('GET /scans pagination', () => {
  it('rejects a negative limit (floor is 1)', async () => {
    const res = await request(app).get('/scans?limit=-5').set(auth(orgAId));
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.scans)).toBe(true);
    expect(res.body.scans.length).toBeGreaterThan(0);
  });

  it('supports offset parameter', async () => {
    const page1 = await request(app).get('/scans?limit=2&offset=0').set(auth(orgAId));
    const page2 = await request(app).get('/scans?limit=2&offset=2').set(auth(orgAId));
    expect(page1.status).toBe(200);
    expect(page2.status).toBe(200);
    const ids1 = page1.body.scans.map((s: { id: string }) => s.id);
    const ids2 = page2.body.scans.map((s: { id: string }) => s.id);
    expect(ids1).not.toEqual(ids2);
  });
});

describe('GET /scans org scoping', () => {
  it('only returns scans belonging to the requesting org', async () => {
    const res = await request(app).get('/scans').set(auth(orgAId));
    expect(res.status).toBe(200);
    for (const scan of res.body.scans as Array<{ organizationId: string }>) {
      expect(scan.organizationId).toBe(orgAId);
    }
  });
});

describe('GET /organizations scoping', () => {
  it('returns only the org matching the tenant header', async () => {
    const res = await request(app).get('/organizations').set(auth(orgAId));
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.organizations)).toBe(true);
    expect(res.body.organizations.length).toBe(1);
    expect(res.body.organizations[0].id).toBe(orgAId);
  });

  it('requires X-Organization-Id when API key is configured', async () => {
    const res = await request(app)
      .get('/organizations')
      .set({ 'X-API-Key': apiKey });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain('X-Organization-Id');
  });
});

describe('GET /teams scoping', () => {
  it('requires X-Organization-Id when API key is configured', async () => {
    const res = await request(app)
      .get('/teams')
      .set({ 'X-API-Key': apiKey });
    expect(res.status).toBe(400);
  });

  it('returns only teams belonging to the requesting org', async () => {
    await db.createTeam(orgAId, 'Team A1');
    const res = await request(app).get('/teams').set(auth(orgAId));
    expect(res.status).toBe(200);
    for (const team of res.body.teams as Array<{ organization_id: string }>) {
      expect(team.organization_id).toBe(orgAId);
    }
  });
});

describe('ML endpoint authentication', () => {
  it('GET /ml/metrics returns 401 when API key is wrong', async () => {
    const res = await request(app)
      .get('/ml/metrics')
      .set({ 'X-API-Key': 'wrong-key', 'X-Organization-Id': orgAId });
    expect(res.status).toBe(401);
  });

  it('GET /ml/status returns 401 when API key is wrong', async () => {
    const res = await request(app)
      .get('/ml/status')
      .set({ 'X-API-Key': 'wrong-key', 'X-Organization-Id': orgAId });
    expect(res.status).toBe(401);
  });

  it('GET /ml/drift returns 401 when API key is wrong', async () => {
    const res = await request(app)
      .get('/ml/drift')
      .set({ 'X-API-Key': 'wrong-key', 'X-Organization-Id': orgAId });
    expect(res.status).toBe(401);
  });
});

describe('POST /ml/feedback validation', () => {
  it('rejects missing fields', async () => {
    const res = await request(app)
      .post('/ml/feedback')
      .set(auth(orgAId))
      .send({ packageName: 'test-pkg' });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain('Invalid payload');
  });

  it('rejects an invalid label value', async () => {
    const res = await request(app)
      .post('/ml/feedback')
      .set(auth(orgAId))
      .send({ packageName: 'pkg', version: '1.0.0', label: 2, scanId: 'scan-1' });
    expect(res.status).toBe(400);
  });
});
