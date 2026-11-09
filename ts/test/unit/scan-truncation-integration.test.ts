import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { scan } from '../../src/scan';
import { SCAN_COVERAGE_LIMITS } from '../../src/lib/config';

describe('scan truncation metadata', () => {
  const tempRoots: string[] = [];

  afterEach(() => {
    for (const root of tempRoots.splice(0)) {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('reports project package root cap in scanTruncations', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nv-roots-cap-'));
    tempRoots.push(root);
    fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'root' }));

    for (let i = 0; i < SCAN_COVERAGE_LIMITS.PROJECT_PACKAGE_ROOTS + 3; i += 1) {
      const dir = path.join(root, 'workspaces', `w-${i}`);
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: `w-${i}` }));
    }

    const result = await scan(root, {
      depth: 5,
      iocEnabled: false,
      dependencyConfusionEnabled: false,
      scanDependencySource: false,
      scanLifecycleScripts: false,
    });

    const cap = result.scanTruncations?.caps.find((c) => c.id === 'projectPackageRoots');
    expect(cap).toMatchObject({
      limit: SCAN_COVERAGE_LIMITS.PROJECT_PACKAGE_ROOTS,
      processed: SCAN_COVERAGE_LIMITS.PROJECT_PACKAGE_ROOTS,
      skipped: 4,
    });
  });
});
