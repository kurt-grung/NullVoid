/**
 * IoC Providers Unit Tests
 */

import { describe, it, expect } from '@jest/globals';
import { createSnykProvider } from '../../src/lib/providers/snyk';
import { createNpmAdvisoriesProvider } from '../../src/lib/providers/npmAdvisories';
import { createGHSAProvider } from '../../src/lib/providers/ghsa';
import { createCVEProvider } from '../../src/lib/providers/cve';
import type { IoCProviderConfig } from '../../src/types/ioc-types';

describe('IoC Providers', () => {
  describe('Snyk Provider', () => {
    it('should create provider with config', () => {
      const config: IoCProviderConfig = {
        enabled: true,
        apiKey: 'test-key',
        rateLimit: 60,
        cacheTTL: 3600000,
        timeout: 10000,
        maxRetries: 3,
        retryDelay: 1000
      };
      const provider = createSnykProvider(config);
      expect(provider.name).toBe('snyk');
      expect(provider.config.apiKey).toBe('test-key');
    });

    it('should check availability correctly', () => {
      const providerWithKey = createSnykProvider({
        enabled: true,
        apiKey: 'test-key',
        rateLimit: 60,
        cacheTTL: 3600000,
        timeout: 10000,
        maxRetries: 3,
        retryDelay: 1000
      });
      expect(providerWithKey.isAvailable()).toBe(true);

      const providerWithoutKey = createSnykProvider({
        enabled: true,
        apiKey: '',
        rateLimit: 60,
        cacheTTL: 3600000,
        timeout: 10000,
        maxRetries: 3,
        retryDelay: 1000
      });
      expect(providerWithoutKey.isAvailable()).toBe(false);
    });
  });

  describe('npm Advisories Provider', () => {
    it('should create provider', () => {
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
      expect(provider.name).toBe('npm');
    });

    it('should be available by default', () => {
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
      expect(provider.isAvailable()).toBe(true);
    });
  });

  describe('GHSA Provider', () => {
    it('should create provider', () => {
      const config: IoCProviderConfig = {
        enabled: true,
        apiKey: '',
        rateLimit: 5000,
        cacheTTL: 3600000,
        timeout: 15000,
        maxRetries: 3,
        retryDelay: 2000
      };
      const provider = createGHSAProvider(config);
      expect(provider.name).toBe('ghsa');
    });
  });

  describe('CVE Provider', () => {
    it('should create provider', () => {
      const config: IoCProviderConfig = {
        enabled: true,
        apiKey: '',
        rateLimit: 10,
        cacheTTL: 86400000,
        timeout: 20000,
        maxRetries: 5,
        retryDelay: 5000
      };
      const provider = createCVEProvider(config);
      expect(provider.name).toBe('cve');
    });
  });
});
