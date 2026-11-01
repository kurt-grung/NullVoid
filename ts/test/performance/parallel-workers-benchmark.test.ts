import { describe, it, expect } from '@jest/globals';
import { scan } from '../../src/scan';
import {
  chunkPackages,
  getOptimalChunkSize,
  getOptimalWorkerCount,
} from '../../src/lib/parallel';

const SCAN_CEILING_MS = 30_000;

describe('parallel worker performance', () => {
  it('getOptimalWorkerCount stays within configured bounds', () => {
    const count = getOptimalWorkerCount();
    expect(count).toBeGreaterThanOrEqual(1);
    expect(count).toBeLessThanOrEqual(8);
  });

  it('chunkPackages distributes items without loss', () => {
    const items = Array.from({ length: 47 }, (_, index) => index);
    const workerCount = getOptimalWorkerCount();
    const chunkSize = getOptimalChunkSize(items.length, workerCount);
    const chunks = chunkPackages(items, chunkSize);
    const flattened = chunks.flat();
    expect(flattened).toHaveLength(items.length);
    expect([...flattened].sort((a, b) => a - b)).toEqual(items);
  });

  it(`parallel scan completes under ${SCAN_CEILING_MS}ms on fixtures`, async () => {
    const fixtures = `${__dirname}/../fixtures`;
    const start = Date.now();
    const result = await scan(fixtures, { depth: 1, iocEnabled: false, parallel: true });
    const duration = Date.now() - start;
    expect(result).toBeDefined();
    expect(duration).toBeLessThan(SCAN_CEILING_MS);
  }, SCAN_CEILING_MS + 5_000);
});
