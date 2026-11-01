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
});
