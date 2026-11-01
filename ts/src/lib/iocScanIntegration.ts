/**
 * IoC Scan Integration
 * Integrates IoC providers into the scan pipeline
 */

import type { Threat } from '../types/core';
import type {
  IoCResult,
  IoCProviderName,
  IoCProviderConfig,
  IoCQueryOptions,
} from '../types/ioc-types';
import { getIoCManager } from './iocIntegration';
import { registerAllProviders } from './providers';
import { createSnykProvider } from './providers/snyk';
import { createNpmAdvisoriesProvider } from './providers/npmAdvisories';
import { createGHSAProvider } from './providers/ghsa';
import { createCVEProvider } from './providers/cve';
import { IOC_CONFIG } from './config';
import { logger } from './logger';
import { createThreat } from '../types/core';

/**
 * Initialize IoC providers
 */
let providersInitialized = false;

function initializeProviders(): void {
  if (providersInitialized) {
    return;
  }

  // Register all providers
  registerAllProviders();

  // Initialize and register providers with IoC manager
  const ioCManager = getIoCManager();

  // Register Snyk provider
  if (IOC_CONFIG.PROVIDERS['snyk'].enabled) {
    const snykBase = IOC_CONFIG.PROVIDERS['snyk'];
    const snykConfig: Partial<IoCProviderConfig> = {
      enabled: snykBase.enabled,
      rateLimit: snykBase.rateLimit,
      cacheTTL: snykBase.cacheTTL,
      timeout: snykBase.timeout,
      maxRetries: snykBase.maxRetries,
      retryDelay: snykBase.retryDelay,
    };
    if (snykBase.apiKey) {
      snykConfig.apiKey = snykBase.apiKey;
    }
    const snykProvider = createSnykProvider(snykConfig);
    ioCManager.registerProvider(snykProvider);
  }

  // Register npm Advisories provider
  if (IOC_CONFIG.PROVIDERS['npm'].enabled) {
    const npmProvider = createNpmAdvisoriesProvider(IOC_CONFIG.PROVIDERS['npm']);
    ioCManager.registerProvider(npmProvider);
  }

  // Register GHSA provider
  if (IOC_CONFIG.PROVIDERS['ghsa'].enabled) {
    const ghsaBase = IOC_CONFIG.PROVIDERS['ghsa'];
    const ghsaConfig: Partial<IoCProviderConfig> = {
      enabled: ghsaBase.enabled,
      rateLimit: ghsaBase.rateLimit,
      cacheTTL: ghsaBase.cacheTTL,
      timeout: ghsaBase.timeout,
      maxRetries: ghsaBase.maxRetries,
      retryDelay: ghsaBase.retryDelay,
    };
    if (ghsaBase.apiKey) {
      ghsaConfig.apiKey = ghsaBase.apiKey;
    }
    const ghsaProvider = createGHSAProvider(ghsaConfig);
    ioCManager.registerProvider(ghsaProvider);
  }

  // Register CVE provider
  if (IOC_CONFIG.PROVIDERS['cve'].enabled) {
    const cveBase = IOC_CONFIG.PROVIDERS['cve'];
    const cveConfig: Partial<IoCProviderConfig> = {
      enabled: cveBase.enabled,
      rateLimit: cveBase.rateLimit,
      cacheTTL: cveBase.cacheTTL,
      timeout: cveBase.timeout,
      maxRetries: cveBase.maxRetries,
      retryDelay: cveBase.retryDelay,
    };
    if (cveBase.apiKey) {
      cveConfig.apiKey = cveBase.apiKey;
    }
    const cveProvider = createCVEProvider(cveConfig);
    ioCManager.registerProvider(cveProvider);
  }

  providersInitialized = true;
  logger.debug('IoC providers initialized');
}

/**
 * Convert IoC result to Threat
 */
function iocResultToThreat(iocResult: IoCResult, packageJsonPath?: string): Threat {
  // Map IoC severity to threat severity
  const severityMap: Record<string, Threat['severity']> = {
    CRITICAL: 'CRITICAL',
    HIGH: 'HIGH',
    MEDIUM: 'MEDIUM',
    LOW: 'LOW',
    INFO: 'LOW',
  };

  const severity = severityMap[iocResult.severity] || 'MEDIUM';

  // Build threat message - use "Vulnerability found: CVE..." format
  let message: string;
  if (iocResult.cve) {
    const cveId = iocResult.cve.id;
    message = `Vulnerability found: ${cveId}`;
  } else {
    message = `Vulnerability found: ${iocResult.vulnerabilityId}`;
  }

  // Build details - more concise format
  let details = iocResult.description;
  if (iocResult.affectedVersions) {
    details += ` Affected versions: ${iocResult.affectedVersions}`;
  }
  if (iocResult.fixedVersions && iocResult.fixedVersions.length > 0) {
    details += ` Fixed in: ${iocResult.fixedVersions.join(', ')}`;
  }
  if (iocResult.cvss) {
    details += ` CVSS Score: ${iocResult.cvss.baseScore} (${iocResult.cvss.version})`;
  }
  if (iocResult.references.length > 0) {
    details += ` References: ${iocResult.references
      .slice(0, 2)
      .map((ref) => {
        // Shorten long URLs
        if (ref.length > 60) {
          return ref.substring(0, 57) + '...';
        }
        return ref;
      })
      .join(', ')}`;
  }

  // Determine threat type based on source
  // Use VULNERABLE_PACKAGE as the base type, which is already defined in ThreatType
  let threatType: Threat['type'] = 'VULNERABLE_PACKAGE';

  return createThreat(
    threatType,
    message,
    packageJsonPath || '', // filePath - use package.json path if provided
    packageJsonPath ? 'package.json' : iocResult.packageName, // filename - show package.json if path provided
    severity,
    details,
    {
      confidence: 0.9, // High confidence for IoC results
      metadata: {
        packageName: iocResult.packageName,
        version: iocResult.version,
        vulnerabilityId: iocResult.vulnerabilityId,
        source: iocResult.source,
        cvss: iocResult.cvss,
        cve: iocResult.cve?.id,
        references: iocResult.references,
      },
      package: iocResult.packageName,
    }
  );
}

/**
 * Query IoC providers for package vulnerabilities
 */
export async function queryIoCProviders(
  packageName: string,
  version?: string,
  providerNames?: IoCProviderName[],
  packageJsonPath?: string
): Promise<Threat[]> {
  // Initialize providers if not already done
  initializeProviders();

  const ioCManager = getIoCManager();
  const threats: Threat[] = [];

  try {
    // Query all enabled providers
    const queryOptions: IoCQueryOptions = {
      packageName,
      maxResults: IOC_CONFIG.DEFAULT_QUERY_OPTIONS.maxResults,
    };
    if (version) {
      queryOptions.version = version;
    }
    const aggregatedResults = await ioCManager.queryAll(queryOptions, providerNames);

    // Convert IoC results to threats
    // Deduplicate by CVE ID or vulnerability ID across all packages
    const seenVulnerabilities = new Set<string>();

    for (const packageKey in aggregatedResults.byPackage) {
      const iocResults = aggregatedResults.byPackage[packageKey] || [];

      for (const iocResult of iocResults) {
        // Create unique key for deduplication (prefer CVE ID if available)
        const dedupKey = iocResult.cve?.id
          ? `cve-${iocResult.cve.id}-${iocResult.packageName}`
          : `${iocResult.vulnerabilityId}-${iocResult.packageName}-${iocResult.source}`;

        // Deduplicate if configured
        if (IOC_CONFIG.AGGREGATION.deduplicate && seenVulnerabilities.has(dedupKey)) {
          continue;
        }

        seenVulnerabilities.add(dedupKey);
        const threat = iocResultToThreat(iocResult, packageJsonPath);
        threats.push(threat);
      }
    }

    logger.debug(
      `IoC query for ${packageName}@${version || 'latest'} returned ${threats.length} threats`,
      {}
    );
  } catch (error) {
    logger.warn(`IoC query failed for ${packageName}`, {
      error: error instanceof Error ? error.message : String(error),
    });
  }

  return threats;
}

/**
 * Merge IoC threats with existing threats
 * Updates severity based on IoC data and deduplicates
 * IoC threats are added alongside static analysis threats for unified display
 */
export function mergeIoCThreats(existingThreats: Threat[], iocThreats: Threat[]): Threat[] {
  const merged: Threat[] = [...existingThreats];
  const seenVulnerabilities = new Set<string>();

  // Track existing vulnerabilities by CVE ID or vulnerability ID
  for (const threat of existingThreats) {
    const metadata = threat.metadata as
      | { cve?: string; vulnerabilityId?: string; packageName?: string }
      | undefined;
    if (metadata?.cve) {
      seenVulnerabilities.add(`cve-${metadata.cve}`);
    } else if (metadata?.vulnerabilityId) {
      seenVulnerabilities.add(`vuln-${metadata.vulnerabilityId}-${metadata.packageName || ''}`);
    }
  }

  // Add IoC threats that don't conflict with existing
  for (const iocThreat of iocThreats) {
    const iocMetadata = iocThreat.metadata as
      | { cve?: string; vulnerabilityId?: string; packageName?: string }
      | undefined;
    const vulnKey = iocMetadata?.cve
      ? `cve-${iocMetadata.cve}`
      : `vuln-${iocMetadata?.vulnerabilityId || ''}-${iocMetadata?.packageName || ''}`;

    // Skip if we've already seen this vulnerability
    if (seenVulnerabilities.has(vulnKey)) {
      continue;
    }

    // Check if we should upgrade severity of existing threat for the same package
    const existingThreat = existingThreats.find((t) => {
      const tMetadata = t.metadata as { packageName?: string } | undefined;
      const iocPkg = iocMetadata?.packageName;
      return (
        tMetadata?.packageName === iocPkg &&
        (t.type === 'SUSPICIOUS_DEPENDENCY' || t.type === 'VULNERABLE_PACKAGE')
      );
    });

    if (existingThreat) {
      // Upgrade severity if IoC threat is more severe
      const severityOrder: Record<string, number> = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
      const existingSeverity = severityOrder[existingThreat.severity] || 0;
      const iocSeverity = severityOrder[iocThreat.severity] || 0;

      if (iocSeverity > existingSeverity) {
        existingThreat.severity = iocThreat.severity;
        existingThreat.confidence = Math.max(
          existingThreat.confidence || 0,
          iocThreat.confidence || 0
        );

        // Merge details - append IoC information
        if (iocThreat.details) {
          existingThreat.details = `${existingThreat.details}\n\nIoC Data: ${iocThreat.details}`;
        }

        // Merge metadata
        if (iocThreat.metadata) {
          existingThreat.metadata = { ...existingThreat.metadata, ...iocThreat.metadata };
        }
      }
      seenVulnerabilities.add(vulnKey);
    } else {
      // Add new IoC threat - these will appear alongside static analysis threats
      // They're properly sorted by severity, so CRITICAL IoC threats appear at bottom with CRITICAL static threats
      merged.push(iocThreat);
      seenVulnerabilities.add(vulnKey);
    }
  }

  return merged;
}
