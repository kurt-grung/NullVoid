import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { jest } from '@jest/globals';
import request from 'supertest';

const repoRoot = path.resolve(__dirname, '../../..');
const fixturesTarget = 'ts/test/fixtures';

describe('API custom rules', () => {
  let dbPath: string;
  let app: import('express').Application;

  beforeAll(async () => {
    dbPath = path.join(os.tmpdir(), `nullvoid-custom-rules-${Date.now()}.db`);
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

  it('POST /rules/validate accepts valid inline rules', async () => {
    const res = await request(app)
      .post('/rules/validate')
      .send({
        rules: {
          custom: {
            patterns: ['eval\\s*\\('],
            severity: 'HIGH',
            description: 'eval',
            confidence_threshold: 0.7,
          },
        },
      });
    expect(res.status).toBe(200);
    expect(res.body.valid).toBe(true);
  });

  it('POST /rules/validate rejects invalid rules', async () => {
    const res = await request(app)
      .post('/rules/validate')
      .send({
        rules: {
          bad: {
            patterns: ['('],
            severity: 'HIGH',
            description: 'bad regex',
            confidence_threshold: 0.7,
          },
        },
      });
    expect(res.status).toBe(400);
    expect(res.body.valid).toBe(false);
    expect(res.body.errors.length).toBeGreaterThan(0);
  });

  it('GET /rules/template returns YAML content', async () => {
    const res = await request(app).get('/rules/template');
    expect(res.status).toBe(200);
    expect(res.text).toContain('detection_rules');
  });

  it('POST /scan applies inline custom rules', async () => {
    const res = await request(app)
      .post('/scan')
      .send({
        target: fixturesTarget,
        mergeRulesWithDefaults: false,
        rules: {
          fixture_rule: {
            patterns: ['hexArray'],
            severity: 'HIGH',
            description: 'fixture marker',
            confidence_threshold: 0.8,
          },
        },
      });
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('completed');
    const types = (res.body.result?.threats ?? []).map((t: { type: string }) => t.type);
    expect(types.some((t: string) => t.includes('FIXTURE_RULE'))).toBe(true);
  });
});
