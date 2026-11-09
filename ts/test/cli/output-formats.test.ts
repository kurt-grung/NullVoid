/**
 * CLI smoke tests for every output format: the built binary is spawned
 * against the fixtures and each format's output is checked for shape; SARIF
 * is validated against the vendored 2.1.0 schema.
 */
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import Ajv from 'ajv';

const BIN = path.resolve(__dirname, '../../dist/bin/nullvoid.js');
const FIXTURES = path.resolve(__dirname, '../fixtures');
const BENIGN = path.join(FIXTURES, 'benign');
const SCHEMA = path.join(FIXTURES, 'schema', 'sarif-schema-2.1.0.json');
const BASE = ['--no-ioc', '--no-dependency-source'];

function run(args: string[]): { code: number; stdout: string; stderr: string } {
  const r = spawnSync(process.execPath, [BIN, ...args], {
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
    timeout: 60000,
  });
  return { code: r.status ?? -1, stdout: r.stdout, stderr: r.stderr };
}

function withOutput(format: string, extra: string[] = []): { code: number; text: string } {
  const out = path.join(
    os.tmpdir(),
    `nv-fmt-${format}-${Date.now()}-${Math.random().toString(36).slice(2)}`
  );
  const r = run([FIXTURES, ...BASE, '--format', format, '--output', out, ...extra]);
  const text = fs.existsSync(out) ? fs.readFileSync(out, 'utf8') : '';
  if (fs.existsSync(out)) fs.unlinkSync(out);
  return { code: r.code, text };
}

const d = fs.existsSync(BIN) ? describe : describe.skip;

d('nullvoid CLI output formats', () => {
  it('json: parseable, carries threats, summary and metadata', () => {
    const { code, text } = withOutput('json');
    expect(code).toBe(1);
    const parsed = JSON.parse(text) as {
      threats: Array<{ type: string; severity: string; filePath: string }>;
      summary: { threatsFound: number; totalFiles: number };
      metadata: { target: string; scanTime: string };
      riskAssessment: { overall: number };
    };
    expect(parsed.threats.length).toBe(parsed.summary.threatsFound);
    expect(parsed.summary.totalFiles).toBeGreaterThan(0);
    expect(parsed.metadata.target).toBe(FIXTURES);
    expect(parsed.threats.some((t) => t.severity === 'CRITICAL')).toBe(true);
    expect(parsed.riskAssessment.overall).toBeGreaterThan(0);
  });

  it('sarif: validates against the SARIF 2.1.0 schema and maps severities', () => {
    const { code, text } = withOutput('sarif');
    expect(code).toBe(1);
    const sarif = JSON.parse(text) as {
      version: string;
      runs: Array<{
        tool: { driver: { name: string; rules?: Array<{ id: string }> } };
        results: Array<{ ruleId: string; level: string; locations: unknown[] }>;
      }>;
    };
    const ajv = new Ajv({ schemaId: 'auto', allErrors: true });
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    ajv.addMetaSchema(require('ajv/lib/refs/json-schema-draft-04.json'));
    const validate = ajv.compile(JSON.parse(fs.readFileSync(SCHEMA, 'utf8')));
    const valid = validate(sarif);
    expect(validate.errors ?? []).toEqual([]);
    expect(valid).toBe(true);

    expect(sarif.version).toBe('2.1.0');
    const run0 = sarif.runs[0]!;
    expect(run0.tool.driver.name.toLowerCase()).toContain('nullvoid');
    expect(run0.results.length).toBeGreaterThan(0);
    expect(run0.results.every((r) => ['error', 'warning', 'note', 'none'].includes(r.level))).toBe(
      true
    );
    expect(run0.results.every((r) => r.locations.length > 0)).toBe(true);
    const ruleIds = new Set((run0.tool.driver.rules ?? []).map((r) => r.id));
    expect(run0.results.every((r) => ruleIds.has(r.ruleId))).toBe(true);
  });

  it('html: a complete document with the threats table', () => {
    const { code, text } = withOutput('html');
    expect(code).toBe(1);
    expect(text).toMatch(/^\s*<!doctype html>/i);
    expect(text).toContain('</html>');
    expect(text).toMatch(/CRITICAL/);
  });

  it('markdown: headed report listing threats', () => {
    const { code, text } = withOutput('markdown');
    expect(code).toBe(1);
    expect(text).toMatch(/^# NullVoid Security Scan Report/m);
    expect(text).toMatch(/^## Threats \(\d+\)/m);
    expect(text).toMatch(/\(CRITICAL\)/);
    expect(text).toMatch(/\*\*Threats Found:\*\* \d+/);
  });

  it('text: human summary on stdout', () => {
    const r = run([FIXTURES, ...BASE, '--format', 'text']);
    expect(r.code).toBe(1);
    expect(r.stdout).toMatch(/threat/i);
    expect(r.stdout).toMatch(/CRITICAL|HIGH/);
  });

  it('--sarif <file> writes SARIF alongside another format', () => {
    const sarifPath = path.join(os.tmpdir(), `nv-sarif-${Date.now()}.sarif`);
    const r = run([FIXTURES, ...BASE, '--format', 'text', '--sarif', sarifPath]);
    expect(r.code).toBe(1);
    const sarif = JSON.parse(fs.readFileSync(sarifPath, 'utf8')) as { version: string };
    expect(sarif.version).toBe('2.1.0');
    fs.unlinkSync(sarifPath);
  });

  it('benign fixtures exit 0 in every format', () => {
    for (const format of ['json', 'sarif', 'html', 'markdown', 'text']) {
      expect(run([BENIGN, ...BASE, '--format', format]).code).toBe(0);
    }
  });

  it('--help lists the scan options once and hides the deprecated flags', () => {
    const r = run(['--help']);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('--fail-on');
    expect(r.stdout).toContain('--max-dir-depth');
    expect(r.stdout).not.toContain('--parallel');
    expect(r.stdout).not.toContain('--workers');
  });
});
