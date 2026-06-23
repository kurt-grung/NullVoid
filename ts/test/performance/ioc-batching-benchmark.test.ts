import { describe, it, expect } from '@jest/globals';
import { RequestBatcher } from '../../src/lib/network/requestBatcher';

const IOC_PROVIDER_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const REQUEST_COUNT = 100;
const MAX_DURATION_MS = 5_000;

describe('IoC request batching performance', () => {
  it(`batches ${REQUEST_COUNT} provider requests under ${MAX_DURATION_MS}ms`, async () => {
    const batcher = new RequestBatcher({ maxBatchSize: 10, batchTimeout: 50 });
    const start = Date.now();
    const results = await Promise.all(
      Array.from({ length: REQUEST_COUNT }, (_, index) =>
        batcher.addRequest(
          `${IOC_PROVIDER_BASE}?cveId=CVE-2024-${String(index).padStart(5, '0')}`,
          { priority: 1 },
          async () => {
            await new Promise((resolve) => setTimeout(resolve, 1));
            return { cve: index };
          }
        )
      )
    );
    const duration = Date.now() - start;
    expect(results).toHaveLength(REQUEST_COUNT);
    expect(duration).toBeLessThan(MAX_DURATION_MS);
  }, MAX_DURATION_MS + 2_000);
});
