/**
 * CLI smoke tests: run the built binary and check the exit-code contract and
 * that multi-word flags reach the scanner.
 *
 *   0  no threats at or above --fail-on (default HIGH)
 *   1  at least one such threat
 *   2  scan error (bad flag value, missing target)
 */
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const BIN = path.resolve(__dirname, '../../dist/bin/nullvoid.js');
const FIXTURES = path.resolve(__dirname, '../fixtures');
const BASE = ['--no-ioc', '--no-dependency-source'];

function run(
  args: string[],
  env: NodeJS.ProcessEnv = {}
): { code: number; stdout: string; stderr: string } {
  const r = spawnSync(process.execPath, [BIN, ...args], {
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1', ...env },
    timeout: 60000,
  });
  return { code: r.status ?? -1, stdout: r.stdout, stderr: r.stderr };
}

const built = fs.existsSync(BIN);
const d = built ? describe : describe.skip;

d('nullvoid CLI exit codes', () => {
  let cleanDir: string;

  beforeAll(() => {
    cleanDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nv-cli-clean-'));
    fs.writeFileSync(path.join(cleanDir, 'index.js'), 'module.exports = (a, b) => a + b;\n');
  });

  afterAll(() => {
    fs.rmSync(cleanDir, { recursive: true, force: true });
  });

  it('exits 0 for a clean directory', () => {
    expect(run([cleanDir, ...BASE]).code).toBe(0);
  });

  it('exits 1 when HIGH or CRITICAL threats are found (default --fail-on high)', () => {
    expect(run([FIXTURES, ...BASE]).code).toBe(1);
  });

  it.each(['json', 'sarif', 'markdown', 'html', 'text'])('exits 1 with --format %s', (format) => {
    expect(run([FIXTURES, ...BASE, '--format', format]).code).toBe(1);
  });

  it('still writes --output when exiting 1', () => {
    const out = path.join(os.tmpdir(), `nv-cli-${Date.now()}.json`);
    const r = run([FIXTURES, ...BASE, '--format', 'json', '--output', out]);
    expect(r.code).toBe(1);
    const parsed = JSON.parse(fs.readFileSync(out, 'utf8')) as { threats: unknown[] };
    expect(parsed.threats.length).toBeGreaterThan(0);
    fs.unlinkSync(out);
  });

  it('exits 0 with --fail-on none even when threats are found', () => {
    expect(run([FIXTURES, ...BASE, '--fail-on', 'none']).code).toBe(0);
  });

  it('exits 1 with --fail-on critical when a CRITICAL threat exists', () => {
    expect(run([FIXTURES, ...BASE, '--fail-on', 'critical']).code).toBe(1);
  });

  it('exits 2 for an invalid --fail-on value', () => {
    const r = run([FIXTURES, ...BASE, '--fail-on', 'bogus']);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain('--fail-on');
  });

  it('exits 2 for a target path that does not exist', () => {
    const r = run([path.join(os.tmpdir(), 'nv-does-not-exist-' + Date.now()), ...BASE]);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain('target not found');
  });

  it('exits 2 for an invalid --max-dir-depth', () => {
    expect(run([cleanDir, ...BASE, '--max-dir-depth', 'abc']).code).toBe(2);
  });
});

d('nullvoid CLI multi-word flags reach the scanner', () => {
  it('--save-history writes a history entry', () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'nv-cli-home-'));
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nv-cli-sh-'));
    fs.writeFileSync(path.join(dir, 'index.js'), 'module.exports = 1;\n');
    const r = run([dir, ...BASE, '--save-history', '--format', 'json'], {
      HOME: home,
      USERPROFILE: home,
    });
    expect(r.code).toBe(0);
    const histDir = path.join(home, '.nullvoid', 'history');
    expect(fs.existsSync(histDir)).toBe(true);
    expect(fs.readdirSync(histDir).length).toBeGreaterThan(0);
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('--export-training writes a JSONL file', () => {
    const out = path.join(os.tmpdir(), `nv-cli-train-${Date.now()}.jsonl`);
    const r = run([FIXTURES, ...BASE, '--export-training', out, '--fail-on', 'none']);
    expect(r.code).toBe(0);
    expect(fs.existsSync(out)).toBe(true);
    fs.unlinkSync(out);
  });
});
