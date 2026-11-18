/**
 * Test shim: the API tests do `request(require('../src/index'))`. Under jest.nitro.config.js
 * that require resolves here instead, which boots the *built* Nitro server (.output/) as a
 * child process with the test's current env (DB path, API key, scan root) and returns a
 * Node (req, res) handler that proxies to it. The same unmodified tests then run against Nitro.
 */
import { spawn, type ChildProcess } from 'child_process';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as net from 'net';
import * as path from 'path';

const entry = path.resolve(__dirname, '../.output/server/index.mjs');
const children: ChildProcess[] = (globalThis as any).__nitroChildren ??= [];
if (!(globalThis as any).__nitroExitHook) {
  (globalThis as any).__nitroExitHook = true;
  process.on('exit', () => children.forEach((c) => c.kill()));
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address() as net.AddressInfo;
      srv.close(() => resolve(port));
    });
    srv.on('error', reject);
  });
}

async function waitForPort(port: number, child: ChildProcess, logFile: string): Promise<void> {
  const logs = () => (fs.existsSync(logFile) ? fs.readFileSync(logFile, 'utf8') : '');
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`Nitro exited early:\n${logs()}`);
    const ok = await new Promise<boolean>((resolve) => {
      const s = net.connect(port, '127.0.0.1', () => {
        s.end();
        resolve(true);
      });
      s.on('error', () => resolve(false));
    });
    if (ok) return;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(`Nitro did not start:\n${logs()}`);
}

const ready: Promise<number> = (async () => {
  const port = await freePort();
  // Log to a file, not a pipe: a pipe closes when Jest exits and the server's shutdown
  // logging would then spin on EPIPE.
  const logFile = path.join(os.tmpdir(), `nullvoid-nitro-test-${port}.log`);
  const fd = fs.openSync(logFile, 'w');
  const child = spawn(process.execPath, [entry], {
    env: { ...process.env, PORT: String(port), HOST: '127.0.0.1', NODE_ENV: 'test' },
    stdio: ['ignore', fd, fd],
  });
  fs.closeSync(fd);
  children.push(child);
  await waitForPort(port, child, logFile);
  // Don't let the server keep Jest alive; it is killed on exit and in globalTeardown.
  child.unref();
  return port;
})();

function handler(req: http.IncomingMessage, res: http.ServerResponse): void {
  ready.then(
    (port) => {
      const upstream = http.request(
        { host: '127.0.0.1', port, method: req.method, path: req.url, headers: req.headers },
        (up) => {
          res.writeHead(up.statusCode ?? 502, up.headers);
          up.pipe(res);
        }
      );
      upstream.on('error', (err) => {
        res.statusCode = 502;
        res.end(String(err));
      });
      req.pipe(upstream);
    },
    (err) => {
      res.statusCode = 503;
      res.end(String(err));
    }
  );
}

module.exports = handler;
