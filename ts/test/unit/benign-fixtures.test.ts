/**
 * Fast false-positive guard: ten small packages written the way popular npm
 * packages are (router, deep utils, babel plugin, webpack loader, React hook,
 * git CLI, static-site builder, HTTPS JSON client, hashing, .env parser) must
 * produce no HIGH or CRITICAL finding. The full benchmark corpus
 * (ts/benchmark) is the slow, network-backed version of this check.
 */
import * as fs from 'fs';
import * as path from 'path';
import { describe, it, expect } from '@jest/globals';
import { scan } from '../../src/scan';

const BENIGN = path.resolve(__dirname, '../fixtures/benign');
const packages = fs
  .readdirSync(BENIGN)
  .filter((d) => fs.existsSync(path.join(BENIGN, d, 'package.json')));

describe('benign fixture packages', () => {
  it('has at least ten packages', () => {
    expect(packages.length).toBeGreaterThanOrEqual(10);
  });

  it.each(packages)('%s: no HIGH/CRITICAL threats', async (pkg) => {
    const result = await scan(path.join(BENIGN, pkg), {
      iocEnabled: false,
      dependencyConfusionEnabled: false,
      scanDependencySource: false,
      all: true,
    });
    const loud = result.threats.filter((t) => t.severity === 'HIGH' || t.severity === 'CRITICAL');
    expect(loud.map((t) => `${t.type}: ${t.message}`)).toEqual([]);
    expect(result.filesScanned).toBeGreaterThan(0);
  });
});
