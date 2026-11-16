#!/usr/bin/env node
/**
 * Parity check: runs the same request sequence against the Express build (dist/index.js)
 * and the Nitro build (.output/server/index.mjs), each with its own temp SQLite DB, and
 * diffs status, content type and normalised bodies.
 *
 *   npm run build && npx nitro build && node scripts/compare-express-nitro.mjs
 */
import { spawn } from 'node:child_process';
import * as fs from 'node:fs';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const apiDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = path.resolve(apiDir, '../..');
const SERVERS = {
  express: path.join(apiDir, 'dist/index.js'),
  nitro: path.join(apiDir, '.output/server/index.mjs'),
};

function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer().listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

async function start(name, env) {
  const port = await freePort();
  const dbPath = path.join(os.tmpdir(), `nv-parity-${name}-${Date.now()}.db`);
  const logFile = path.join(os.tmpdir(), `nv-parity-${name}.log`);
  const fd = fs.openSync(logFile, 'w');
  const child = spawn(process.execPath, [SERVERS[name]], {
    env: {
      ...process.env,
      ...env,
      PORT: String(port),
      HOST: '127.0.0.1',
      NULLVOID_DB_PATH: dbPath,
      NULLVOID_SCAN_ROOT: repoRoot,
    },
    stdio: ['ignore', fd, fd],
  });
  fs.closeSync(fd);
  const base = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 200; i++) {
    try {
      await fetch(`${base}/graphql`);
      break;
    } catch {
      await new Promise((r) => setTimeout(r, 50));
    }
  }
  return {
    base,
    stop: () => {
      child.kill();
      for (const s of ['', '-shm', '-wal']) fs.rmSync(dbPath + s, { force: true });
    },
  };
}

const ID = /\b(scan|org|team|sched|wh|audit)-\d{10,}-[a-z0-9]+/g;
const ISO = /\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?Z?/g;
const norm = (s) => s.replace(ID, '$1-<id>').replace(ISO, '<ts>').replace(/"heartbeat":\d+/g, '');

async function call(base, step, ctx) {
  const headers = { ...(step.headers ?? {}) };
  let body;
  if (step.raw !== undefined) {
    headers['content-type'] = 'application/json';
    body = step.raw;
  } else if (step.body !== undefined) {
    headers['content-type'] = 'application/json';
    body = JSON.stringify(typeof step.body === 'function' ? step.body(ctx) : step.body);
  }
  const url = typeof step.path === 'function' ? step.path(ctx) : step.path;
  const res = await fetch(base + url, { method: step.method ?? 'GET', headers, body, redirect: 'manual' });
  const text = await res.text();
  if (step.save) {
    try {
      step.save(ctx, JSON.parse(text));
    } catch {
      /* not JSON */
    }
  }
  const type = (res.headers.get('content-type') ?? '').split(';')[0].trim();
  let shown = norm(text);
  if (step.bodyCheck === 'length') shown = `<${text.length > 0 ? 'non-empty' : 'empty'}>`;
  try {
    if (step.bodyCheck === 'scan') {
      const j = JSON.parse(text);
      shown = JSON.stringify({ status: j.status, threats: j.result?.threats?.length ?? null, error: j.error });
    }
    if (step.bodyCheck === 'json') shown = norm(JSON.stringify(JSON.parse(text)));
  } catch {
    /* not JSON: compare the raw (normalised) text */
  }
  return {
    status: res.status,
    type,
    location: res.headers.get('location') ?? '',
    cors: res.headers.get('access-control-allow-origin') ?? '',
    rateLimit: res.headers.get('ratelimit-limit') ?? '',
    body: shown,
  };
}

const KEY = { 'X-API-Key': 'parity-key' };

const OPEN = [
  { path: '/' },
  { path: '/health' },
  { path: '/health?platform=1' },
  { path: '/api/health' },
  { path: '/api/scans' },
  { path: '/scans?limit=2&offset=0' },
  { path: '/organizations' },
  { method: 'POST', path: '/organizations', body: { name: 'Acme' }, save: (c, j) => (c.org = j.id) },
  { path: (c) => `/organizations/${c.org}` },
  { path: '/organizations/org-missing' },
  { path: '/teams' },
  { method: 'POST', path: '/teams', body: {} },
  { method: 'POST', path: '/teams', body: { organizationId: 'org-missing' } },
  { method: 'POST', path: '/teams', body: (c) => ({ organizationId: c.org, name: 'Red' }), save: (c, j) => (c.team = j.id) },
  { path: (c) => `/teams/${c.team}` },
  { path: (c) => `/teams?organizationId=${c.org}` },
  { path: '/teams/team-missing' },
  { path: '/graphql' },
  { path: '/schedules' },
  { method: 'POST', path: '/schedule', body: {} },
  { method: 'POST', path: '/schedule', body: { target: 'lodash', cronExpression: '0 * * * *' }, save: (c, j) => (c.sched = j.id) },
  { method: 'POST', path: '/schedule', headers: { 'X-NullVoid-Role': 'viewer' }, body: { target: 'x', cronExpression: '* * * * *' } },
  { method: 'DELETE', path: '/schedule/sched-missing' },
  { method: 'DELETE', path: (c) => `/schedule/${c.sched}` },
  { path: '/webhooks' },
  { method: 'POST', path: '/webhooks', body: { url: 'https://example.invalid/hook' } },
  { method: 'POST', path: '/webhooks', body: { url: 'https://example.invalid/hook', events: ['scan.completed'] }, bodyCheck: 'length', save: (c, j) => (c.wh = j.id) },
  { path: '/webhooks' },
  { method: 'DELETE', path: (c) => `/webhooks/${c.wh}` },
  { path: '/audit' },
  { path: '/audit?limit=2', headers: { 'X-NullVoid-Role': 'viewer' } },
  { path: '/rules/template' },
  { path: '/rules/template?format=json', bodyCheck: 'json' },
  { method: 'POST', path: '/rules/validate', body: { rules: { detection_rules: {} } } },
  { method: 'POST', path: '/rules/validate', body: { rules: 'not rules' } },
  { method: 'POST', path: '/scan', body: { target: '../outside' } },
  { method: 'POST', path: '/scan', body: { target: 'evil;curl' } },
  { method: 'POST', path: '/scan', body: {}, bodyCheck: 'scan' },
  { method: 'POST', path: '/scan', body: { target: 'ts/test/fixtures' }, bodyCheck: 'scan', save: (c, j) => (c.scan = j.id) },
  { path: (c) => `/scan/${c.scan}`, bodyCheck: 'scan' },
  { path: (c) => `/report/${c.scan}?format=markdown`, bodyCheck: 'length' },
  { path: (c) => `/report/${c.scan}`, bodyCheck: 'length' },
  { path: '/scan/scan-missing' },
  { path: '/report/scan-missing' },
  { path: '/ml/metrics' },
  { path: '/ml/status' },
  { path: '/ml/drift' },
  { method: 'POST', path: '/ml/feedback', body: { packageName: 'x' } },
  { method: 'OPTIONS', path: '/scan' },
  { path: '/api/api-docs.json', bodyCheck: 'json' },
  { path: '/api/api-docs/', bodyCheck: 'length' },
  { path: '/api/api-docs', expectDiff: 'same 301 + Location; Express adds an HTML "Redirecting" body' },
  { path: '/api-docs.json', bodyCheck: 'json', expectDiff: 'Express bug: its /api strip has no slash boundary, so /api-docs* becomes -docs* and only /api/api-docs works; Nitro serves both' },
  { path: '/api-docs', expectDiff: 'Express bug: its /api strip has no slash boundary, so /api-docs* becomes -docs* and only /api/api-docs works; Nitro serves both' },
  { path: '/api-docs/', bodyCheck: 'length', expectDiff: 'Express bug: its /api strip has no slash boundary, so /api-docs* becomes -docs* and only /api/api-docs works; Nitro serves both' },
  // Known, intentional differences (listed in the report):
  { path: '/does-not-exist', expectDiff: 'unknown route: Express sends an HTML "Cannot GET" page, Nitro JSON {error}' },
  { method: 'POST', path: '/organizations', raw: '{bad', expectDiff: 'malformed JSON: Express 500, Nitro 400' },
];

const KEYED = [
  { path: '/health', expectDiff: undefined },
  { path: '/health', headers: KEY },
  { path: '/scans', headers: KEY },
  { path: '/scans', headers: { ...KEY, 'X-Organization-Id': 'org-a' } },
  { path: '/organizations', headers: KEY },
  { path: '/organizations', headers: { ...KEY, 'X-Organization-Id': 'org-a' } },
  { path: '/teams', headers: { ...KEY, 'X-Organization-Id': 'org-a' } },
  { method: 'POST', path: '/scan', headers: KEY, body: { target: 'lodash' } },
  { path: '/api/api-docs.json', bodyCheck: 'json' },
  { path: '/api-docs.json', bodyCheck: 'json', expectDiff: 'same Express /api-docs prefix bug (Express answers 401)' },
  { path: '/rules/template', headers: { 'X-API-Key': 'wrong' } },
];

async function runMode(label, env, steps) {
  const results = {};
  for (const name of Object.keys(SERVERS)) {
    const srv = await start(name, env);
    const ctx = {};
    results[name] = [];
    try {
      for (const step of steps) results[name].push(await call(srv.base, step, ctx));
    } finally {
      srv.stop();
    }
  }
  let same = 0;
  const diffs = [];
  const expected = [];
  steps.forEach((step, i) => {
    const a = results.express[i];
    const b = results.nitro[i];
    const keys = ['status', 'type', 'location', 'cors', 'rateLimit', 'body'];
    const changed = keys.filter((k) => a[k] !== b[k]);
    const name = `${step.method ?? 'GET'} ${typeof step.path === 'function' ? step.path({ org: ':org', team: ':team', sched: ':id', wh: ':id', scan: ':scan' }) : step.path}`;
    if (!changed.length) same++;
    else if (step.expectDiff) expected.push({ name, why: step.expectDiff, express: a.status, nitro: b.status });
    else diffs.push({ name, changed, express: Object.fromEntries(changed.map((k) => [k, String(a[k]).slice(0, 160)])), nitro: Object.fromEntries(changed.map((k) => [k, String(b[k]).slice(0, 160)])) });
  });
  console.log(`\n== ${label}: ${same}/${steps.length} identical, ${expected.length} expected differences, ${diffs.length} unexpected`);
  for (const e of expected) console.log(`  expected  ${e.name}  (${e.express} vs ${e.nitro})  ${e.why}`);
  for (const d of diffs) {
    console.log(`  DIFF      ${d.name}  [${d.changed.join(', ')}]`);
    console.log(`            express: ${JSON.stringify(d.express)}`);
    console.log(`            nitro:   ${JSON.stringify(d.nitro)}`);
  }
  return diffs.length;
}

const unexpected =
  (await runMode('no API key', { NULLVOID_API_KEY: '' }, OPEN)) +
  (await runMode('API key auth', { NULLVOID_API_KEY: 'parity-key' }, KEYED));
process.exit(unexpected ? 1 : 0);
