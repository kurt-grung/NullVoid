/**
 * IoC Scan Integration Tests
 */

import { describe, it, expect, afterEach } from '@jest/globals';
import { getIoCManager } from '../../src/lib/iocIntegration';
import { queryIoCProviders } from '../../src/lib/iocScanIntegration';
import type { AggregatedIoCResults } from '../../src/types/ioc-types';

describe('IoC Scan Integration', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('should query IoC providers', async () => {
    const threats = await queryIoCProviders('test-package', '1.0.0', ['npm']);

    expect(Array.isArray(threats)).toBe(true);
  });

  it('should query with no providers specified', async () => {
    const queryAllSpy = jest.spyOn(getIoCManager(), 'queryAll').mockResolvedValue({
      byPackage: {},
      providerStats: {} as AggregatedIoCResults['providerStats'],
      totalResults: 0,
      uniqueVulnerabilities: [],
    });

    const threats = await queryIoCProviders('test-package', '1.0.0');

    expect(Array.isArray(threats)).toBe(true);
    expect(queryAllSpy).toHaveBeenCalledWith(
      expect.objectContaining({ packageName: 'test-package', version: '1.0.0' }),
      undefined
    );
  });

  it('should handle errors gracefully', async () => {
    const threats = await queryIoCProviders('nonexistent-package', '999.999.999', ['npm']);

    expect(Array.isArray(threats)).toBe(true);
  });
});
