/**
 * IoC Scan Integration Tests
 */

import { describe, it, expect, afterEach, beforeEach, jest } from '@jest/globals';

// No network: every provider request gets a recorded 404 ("no advisories").
jest.mock('../../src/lib/providers/fetchWithTimeout');

import { useRecordedHttp } from '../helpers/recordedHttp';
import { getIoCManager } from '../../src/lib/iocIntegration';
import { queryIoCProviders } from '../../src/lib/iocScanIntegration';
import type { AggregatedIoCResults } from '../../src/types/ioc-types';

const http = useRecordedHttp();

describe('IoC Scan Integration', () => {
  beforeEach(() => {
    http.reset();
    http.on(/./, 'http-404');
  });

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
