import { describe, it, expect } from '@jest/globals';
import { scan } from '../../src/scan';

describe('scan performance baseline', () => {
  it('scans fixtures under 30s', async () => {
    const fixtures = `${__dirname}/../fixtures`;
    const start = Date.now();
    const result = await scan(fixtures, { depth: 1, iocEnabled: false, parallel: false });
    const duration = Date.now() - start;
    expect(result).toBeDefined();
    expect(duration).toBeLessThan(30_000);
  }, 35_000);
});
