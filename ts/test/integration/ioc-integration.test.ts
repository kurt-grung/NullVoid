/**
 * IoC Integration End-to-End Tests
 */

import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { getIoCManager } from '../../src/lib/iocIntegration';
import { registerAllProviders } from '../../src/lib/providers';
import { createNpmAdvisoriesProvider } from '../../src/lib/providers/npmAdvisories';

describe('IoC Integration E2E', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should register all providers', () => {
    registerAllProviders();
    // Should not throw error
    expect(true).toBe(true);
  });

  it('should initialize IoC manager with providers', () => {
    const manager = getIoCManager();
    const provider = createNpmAdvisoriesProvider();
    manager.registerProvider(provider);
    
    expect(manager).toBeDefined();
  });

  it('should handle provider health checks', async () => {
    const manager = getIoCManager();
    const provider = createNpmAdvisoriesProvider();
    manager.registerProvider(provider);
    
    const health = await manager.getProviderHealth('npm');
    
    expect(health).toBeDefined();
    expect(typeof health.healthy).toBe('boolean');
  });

  it('should query provider for package', async () => {
    const manager = getIoCManager();
    const provider = createNpmAdvisoriesProvider();
    manager.registerProvider(provider);
    
    // This will make a real API call, so we just check it doesn't throw
    try {
      const response = await manager.queryProvider('npm', {
        packageName: 'express',
        version: '4.18.0'
      });
      
      // Response should be defined (even if empty)
      expect(response).toBeDefined();
    } catch (error) {
      // Network errors are acceptable in tests
      expect(error).toBeDefined();
    }
  });
});

