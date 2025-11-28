/**
 * IoC Scan Integration Tests
 */

import { describe, it, expect } from '@jest/globals';
import { queryIoCProviders } from '../../src/lib/iocScanIntegration';

describe('IoC Scan Integration', () => {
  it('should query IoC providers', async () => {
    const threats = await queryIoCProviders('test-package', '1.0.0', ['npm']);
    
    expect(Array.isArray(threats)).toBe(true);
  });

  it('should query with no providers specified', async () => {
    const threats = await queryIoCProviders('test-package', '1.0.0');
    
    expect(Array.isArray(threats)).toBe(true);
  });

  it('should handle errors gracefully', async () => {
    // Even if providers fail, should return empty array
    const threats = await queryIoCProviders('nonexistent-package', '999.999.999', ['npm']);
    
    expect(Array.isArray(threats)).toBe(true);
  });
});
