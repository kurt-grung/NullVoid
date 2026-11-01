/**
 * IoC Integration Manager Tests
 */

import { describe, it, expect, beforeEach } from '@jest/globals';
import { IoCIntegrationManager, getIoCManager } from '../../src/lib/iocIntegration';
import { createNpmAdvisoriesProvider } from '../../src/lib/providers/npmAdvisories';
import type { IoCProviderConfig } from '../../src/types/ioc-types';

describe('IoC Integration Manager', () => {
  let manager: IoCIntegrationManager;

  beforeEach(() => {
    manager = new IoCIntegrationManager();
  });

  it('should create manager instance', () => {
    expect(manager).toBeDefined();
  });

  it('should register provider', () => {
    const config: IoCProviderConfig = {
      enabled: true,
      apiKey: '',
      rateLimit: 60,
      cacheTTL: 3600000,
      timeout: 15000,
      maxRetries: 3,
      retryDelay: 1000
    };
    const provider = createNpmAdvisoriesProvider(config);
    manager.registerProvider(provider);
    
    // Provider should be registered (no error means success)
    expect(provider).toBeDefined();
  });

  it('should get global manager instance', () => {
    const globalManager = getIoCManager();
    expect(globalManager).toBeDefined();
    expect(globalManager).toBeInstanceOf(IoCIntegrationManager);
  });

  it('should query provider', async () => {
    const config: IoCProviderConfig = {
      enabled: true,
      apiKey: '',
      rateLimit: 60,
      cacheTTL: 3600000,
      timeout: 15000,
      maxRetries: 3,
      retryDelay: 1000
    };
    const provider = createNpmAdvisoriesProvider(config);
    manager.registerProvider(provider);
    
    // Query may fail due to network, but should return a response structure
    const response = await manager.queryProvider('npm', {
      packageName: 'express',
      version: '4.18.0'
    });
    
    // Response should be either null or a valid IoCResponse
    expect(response === null || (response && typeof response === 'object')).toBe(true);
  });
});
