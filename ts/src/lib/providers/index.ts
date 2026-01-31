/**
 * IoC Providers Index
 * Exports all IoC providers and registration functions
 */

import type { ProviderRegistryEntry } from '../../types/ioc-types';
import { createSnykProvider, defaultSnykConfig } from './snyk';
import { createNpmAdvisoriesProvider, defaultNpmAdvisoriesConfig } from './npmAdvisories';
import { createGHSAProvider, defaultGHSAConfig } from './ghsa';
import { createCVEProvider, defaultCVEConfig } from './cve';
import { registerIoCProvider } from '../iocIntegration';

/**
 * Register all IoC providers
 */
export function registerAllProviders(): void {
  // Register Snyk provider
  const snykEntry: ProviderRegistryEntry = {
    name: 'snyk',
    factory: (config) => createSnykProvider(config),
    defaultConfig: defaultSnykConfig,
  };
  registerIoCProvider(snykEntry);

  // Register npm Advisories provider
  const npmEntry: ProviderRegistryEntry = {
    name: 'npm',
    factory: (config) => createNpmAdvisoriesProvider(config),
    defaultConfig: defaultNpmAdvisoriesConfig,
  };
  registerIoCProvider(npmEntry);

  // Register GHSA provider
  const ghsaEntry: ProviderRegistryEntry = {
    name: 'ghsa',
    factory: (config) => createGHSAProvider(config),
    defaultConfig: defaultGHSAConfig,
  };
  registerIoCProvider(ghsaEntry);

  // Register CVE/NVD provider
  const cveEntry: ProviderRegistryEntry = {
    name: 'cve',
    factory: (config) => createCVEProvider(config),
    defaultConfig: defaultCVEConfig,
  };
  registerIoCProvider(cveEntry);
}
