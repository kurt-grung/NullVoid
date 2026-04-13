import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
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
  updateScan: (
    id: string,
    updates: { status: string; resultJson?: string; error?: string; completedAt?: string }
  ) => Promise<void>;
};

const apiKey = 'test-api-key';
let dbPath: string;
let app: any;
let db: DbModule;
let orgAId = '';
let teamAId = '';
let orgBId = '';

function authHeaders(orgId?: string, teamId?: string): Record<string, string> {
  const headers: Record<string, string> = {
    'X-API-Key': apiKey,
  };
  if (orgId) headers['X-Organization-Id'] = orgId;
  if (teamId) headers['X-Team-Id'] = teamId;
  return headers;
}

beforeAll(async () => {
  dbPath = path.join(os.tmpdir(), `nullvoid-api-test-${Date.now()}.db`);
  process.env['NULLVOID_DB_PATH'] = dbPath;
  process.env['NULLVOID_API_KEY'] = apiKey;
  process.env['NULLVOID_SCAN_ROOT'] = path.join(os.tmpdir(), 'nullvoid-api-scan-root');

  fs.mkdirSync(process.env['NULLVOID_SCAN_ROOT'], { recursive: true });

  // eslint-disable-next-line @typescript-eslint/no-var-requires
  app = require('../src/index');
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  db = require('../src/db');
  const orgA = await db.createOrganization('Org A');
  const teamA = await db.createTeam(orgA.id, 'Team A');
  const orgB = await db.createOrganization('Org B');
  orgAId = orgA.id;
  teamAId = teamA.id;
  orgBId = orgB.id;
});

afterAll(() => {
  for (const suffix of ['', '-shm', '-wal']) {
    const p = `${dbPath}${suffix}`;
    if (fs.existsSync(p)) {
      fs.rmSync(p, { force: true });
    }
  }
});

describe('API security hardening', () => {
  it('rejects list scans when tenant header is missing', async () => {
    const res = await request(app).get('/scans').set(authHeaders());
    expect(res.status).toBe(400);
    expect(res.body.error).toContain('X-Organization-Id');
  });

  it('rejects path traversal targets in /scan', async () => {
    const res = await request(app)
      .post('/scan')
      .set(authHeaders('org-a'))
      .send({ target: '../outside' });

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('inside configured scan root');
  });

  it('blocks cross-tenant access to scan details and reports', async () => {
    const scanId = `scan-${Date.now()}-tenant`;
    await db.insertScan({
      id: scanId,
      organizationId: orgAId,
      teamId: teamAId,
      target: '/tmp/example',
      status: 'pending',
    });
    await db.updateScan(scanId, {
      status: 'completed',
      resultJson: JSON.stringify({ threats: [], summary: { threatsFound: 0 }, metadata: {} }),
      completedAt: new Date().toISOString(),
    });

    const scanRes = await request(app).get(`/scan/${scanId}`).set(authHeaders(orgBId));
    expect(scanRes.status).toBe(403);

    const reportRes = await request(app)
      .get(`/report/${scanId}`)
      .set(authHeaders(orgBId))
      .query({ format: 'markdown' });
    expect(reportRes.status).toBe(403);
  });

  it('handles malformed stored scan result JSON safely', async () => {
    const scanId = `scan-${Date.now()}-malformed`;
    await db.insertScan({
      id: scanId,
      organizationId: orgAId,
      teamId: teamAId,
      target: '/tmp/example',
      status: 'pending',
    });
    await db.updateScan(scanId, {
      status: 'completed',
      resultJson: '{"broken-json": ',
      completedAt: new Date().toISOString(),
    });

    const res = await request(app)
      .get(`/report/${scanId}`)
      .set(authHeaders(orgAId, teamAId))
      .query({ format: 'markdown' });

    expect(res.status).toBe(500);
    expect(res.body.error).toBe('Stored scan result is invalid JSON');
  });
});
