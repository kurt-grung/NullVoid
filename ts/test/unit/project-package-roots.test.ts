import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { collectProjectPackageRoots } from '../../src/lib/projectPackageRoots';
import { SCAN_COVERAGE_LIMITS } from '../../src/lib/config';

describe('collectProjectPackageRoots', () => {
  const tempRoots: string[] = [];

  afterEach(() => {
    for (const root of tempRoots.splice(0)) {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('counts package.json dirs beyond the project root cap', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nv-roots-'));
    tempRoots.push(root);
    fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'root' }));

    for (let i = 0; i < SCAN_COVERAGE_LIMITS.PROJECT_PACKAGE_ROOTS + 5; i += 1) {
      const dir = path.join(root, 'packages', `pkg-${i}`);
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: `pkg-${i}` }));
    }

    const result = collectProjectPackageRoots(root, { depth: 5 });
    expect(result.discovered).toBe(SCAN_COVERAGE_LIMITS.PROJECT_PACKAGE_ROOTS + 6);
    expect(result.dirs).toHaveLength(SCAN_COVERAGE_LIMITS.PROJECT_PACKAGE_ROOTS);
    expect(result.discovered - result.dirs.length).toBe(6);
  });

  it('bounds directory discovery with maxDirDepth, not the dependency depth', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nv-roots-'));
    tempRoots.push(root);
    fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'root' }));
    const nested = path.join(root, 'a', 'b', 'pkg');
    fs.mkdirSync(nested, { recursive: true });
    fs.writeFileSync(path.join(nested, 'package.json'), JSON.stringify({ name: 'nested' }));

    // A shallow dependency depth must not truncate directory discovery.
    expect(collectProjectPackageRoots(root, { depth: 1 }).dirs).toHaveLength(2);
    // root -> a -> b -> pkg is four levels; maxDirDepth 3 stops before pkg.
    expect(collectProjectPackageRoots(root, { depth: 1, maxDirDepth: 3 }).dirs).toHaveLength(1);
    expect(collectProjectPackageRoots(root, { depth: 1, maxDirDepth: 4 }).dirs).toHaveLength(2);
  });
});
