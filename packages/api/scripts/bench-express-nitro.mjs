#!/usr/bin/env node
/**
 * Benchmarks the Express build against the Nitro build with wrk (brew install wrk).
 * Each server runs alone with its own seeded SQLite DB; reports req/s, p50/p99 latency,
 * cold start (spawn -> first 200) and RSS after load.
 *
 *   npm run build && node scripts/bench-express-nitro.mjs [seconds]
 */
import { execFileSync, spawn } from 'node:child_process';
import * as fs from 'node:fs';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const apiDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DURATION = Number(process.argv[2] ?? 10);
const SERVERS = {
  express: path.join(apiDir, 'dist/index.js'),
  nitro: path.join(apiDir, '.output/server/index.mjs'),
};
const ENDPOINTS = ['/health', '/scans', '/api/organizations'];

const freePort = () =>
  new Promise((resolve) => {
    const s = net.createServer().listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });

async function start(name, dbPath) {
  const port = await freePort();
  const t0 = performance.now();
  const child = spawn(process.execPath, [SERVERS[name]], {
    env: { ...process.env, PORT: String(port), HOST: '127.0.0.1', NULLVOID_DB_PATH: dbPath, NULLVOID_API_KEY: '' },
    stdio: 'ignore',
  });
  const base = `http://127.0.0.1:${port}`;
  for (;;) {
    try {
      if ((await fetch(`${base}/health`)).ok) break;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 5));
  }
  return { child, base, coldMs: performance.now() - t0 };
}

function stop(child) {
  return new Promise((resolve) => {
    child.once('exit', resolve);
    child.kill('SIGKILL');
  });
}

function rssMb(pid) {
  return Number(execFileSync('ps', ['-o', 'rss=', '-p', String(pid)]).toString().trim()) / 1024;
}

function wrk(url) {
  const out = execFileSync('wrk', ['-t4', '-c64', `-d${DURATION}s`, '--latency', url]).toString();
  const rps = Number(/Requests\/sec:\s+([\d.]+)/.exec(out)[1]);
  const toMs = (n, unit) => Number(n) * ({ us: 0.001, ms: 1, s: 1000, m: 60000 }[unit] ?? 1);
  const lat = (q) => {
    const m = new RegExp(`^\\s*${q}%\\s+([\\d.]+)(us|ms|s|m)\\s*$`, 'm').exec(out);
    return m ? toMs(m[1], m[2]) : NaN;
  };
  const p50 = lat(50);
  const p99 = lat(99);
  const errors = /Non-2xx or 3xx responses: (\d+)/.exec(out)?.[1] ?? '0';
  return { rps, p50, p99, errors };
}

async function seed(name) {
  const dbPath = path.join(os.tmpdir(), `nv-bench-${name}-${Date.now()}.db`);
  const { child, base } = await start(name, dbPath);
  for (let i = 0; i < 5; i++) {
    await fetch(`${base}/organizations`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: `Org ${i}` }),
    });
  }
  await stop(child);
  // 50 completed scans so GET /scans returns a realistic page
  const Database = (await import('better-sqlite3')).default;
  const db = new Database(dbPath);
  const cols = db.prepare('PRAGMA table_info(scans)').all().map((c) => c.name);
  const insert = db.prepare(
    `INSERT INTO scans (id, target, status${cols.includes('result_json') ? ', result_json' : ''}) VALUES (?, ?, 'completed'${cols.includes('result_json') ? ", '{\"threats\":[]}'" : ''})`
  );
  for (let i = 0; i < 50; i++) insert.run(`scan-${Date.now()}-${i}`, `pkg-${i}`);
  db.close();
  return dbPath;
}

const results = {};
for (const name of Object.keys(SERVERS)) {
  const dbPath = await seed(name);
  // cold start: median of 5 fresh processes
  const colds = [];
  for (let i = 0; i < 5; i++) {
    const s = await start(name, dbPath);
    colds.push(s.coldMs);
    await stop(s.child);
  }
  colds.sort((a, b) => a - b);
  const s = await start(name, dbPath);
  const rssIdle = rssMb(s.child.pid);
  results[name] = { coldMs: colds[2], rssIdle, endpoints: {} };
  for (const ep of ENDPOINTS) {
    wrk(s.base + ep); // warm-up pass (JIT, caches), discarded
    results[name].endpoints[ep] = wrk(s.base + ep);
  }
  results[name].rssLoaded = rssMb(s.child.pid);
  await stop(s.child);
  for (const sfx of ['', '-shm', '-wal']) fs.rmSync(dbPath + sfx, { force: true });
}

const pct = (a, b) => `${b >= a ? '+' : ''}${(((b - a) / a) * 100).toFixed(0)}%`;
console.log(`\nwrk -t4 -c64 -d${DURATION}s, Node ${process.version}, ${os.cpus()[0].model}\n`);
console.log('endpoint             | express req/s | nitro req/s | change | p50 ms (e/n)  | p99 ms (e/n)  | non-2xx');
for (const ep of ENDPOINTS) {
  const e = results.express.endpoints[ep];
  const n = results.nitro.endpoints[ep];
  console.log(
    `${ep.padEnd(20)} | ${e.rps.toFixed(0).padStart(13)} | ${n.rps.toFixed(0).padStart(11)} | ${pct(e.rps, n.rps).padStart(6)} | ${e.p50.toFixed(2)} / ${n.p50.toFixed(2)}`.padEnd(88) +
      ` | ${e.p99.toFixed(2)} / ${n.p99.toFixed(2)}`.padEnd(16) +
      ` | ${e.errors}/${n.errors}`
  );
}
const e = results.express;
const n = results.nitro;
console.log(`\ncold start (spawn -> first 200, median of 5): express ${e.coldMs.toFixed(0)} ms, nitro ${n.coldMs.toFixed(0)} ms`);
console.log(`RSS idle: express ${e.rssIdle.toFixed(0)} MB, nitro ${n.rssIdle.toFixed(0)} MB`);
console.log(`RSS after load: express ${e.rssLoaded.toFixed(0)} MB, nitro ${n.rssLoaded.toFixed(0)} MB`);
fs.writeFileSync(path.join(os.tmpdir(), 'nv-bench.json'), JSON.stringify(results, null, 2));
