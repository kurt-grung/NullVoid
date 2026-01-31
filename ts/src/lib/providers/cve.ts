/**
 * NVD CVE Database IoC Provider
 * Integration with National Vulnerability Database (NVD) API
 */

import type {
  IoCProvider,
  IoCProviderConfig,
  IoCQueryOptions,
  IoCResponse,
  IoCResult,
  VulnerabilitySeverity,
  CVSSScore,
  CVEInfo,
} from '../../types/ioc-types';
import { logger } from '../logger';
import { providerFetch } from './providerHttpClient';

/**
 * NVD API response types
 */
interface NVDCVE {
  id: string;
  sourceIdentifier: string;
  published: string;
  lastModified: string;
  vulnStatus: string;
  descriptions: Array<{
    lang: string;
    value: string;
  }>;
  metrics?: {
    cvssMetricV31?: Array<{
      source: string;
      type: string;
      cvssData: {
        version: string;
        vectorString: string;
        baseScore: number;
        baseSeverity: string;
      };
    }>;
    cvssMetricV30?: Array<{
      source: string;
      type: string;
      cvssData: {
        version: string;
        vectorString: string;
        baseScore: number;
        baseSeverity: string;
      };
    }>;
    cvssMetricV2?: Array<{
      source: string;
      type: string;
      cvssData: {
        version: string;
        vectorString: string;
        baseScore: number;
        baseSeverity: string;
      };
    }>;
  };
  references: Array<{
    url: string;
    source: string;
  }>;
  configurations?: Array<{
    nodes: Array<{
      operator: string;
      cpeMatch: Array<{
        vulnerable: boolean;
        criteria: string;
        matchCriteriaId: string;
      }>;
    }>;
  }>;
}

interface NVDResponse {
  resultsPerPage: number;
  startIndex: number;
  totalResults: number;
  format: string;
  version: string;
  timestamp: string;
  vulnerabilities: Array<{
    cve: NVDCVE;
  }>;
}

/**
 * NVD CVE Database IoC Provider Implementation
 */
export class CVEProvider implements IoCProvider {
  readonly name = 'cve' as const;
  readonly config: IoCProviderConfig;
  private readonly baseUrl = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

  constructor(config: IoCProviderConfig) {
    this.config = config;
  }

  /**
   * Check if provider is available
   */
  isAvailable(): boolean {
    return this.config.enabled;
  }

  /**
   * Get provider health status
   */
  async getHealth(): Promise<{ healthy: boolean; message?: string }> {
    try {
      // Simple health check - query for a known CVE
      const response = await providerFetch(`${this.baseUrl}?cveId=CVE-2021-44228`, {
        timeout: this.config.timeout,
      });

      if (response.ok) {
        return { healthy: true };
      } else {
        return { healthy: false, message: `API returned status ${response.status}` };
      }
    } catch (error) {
      return {
        healthy: false,
        message: error instanceof Error ? error.message : String(error),
      };
    }
  }

  /**
   * Query vulnerabilities for a package
   * Note: NVD doesn't directly map to npm packages, so we search by keyword
   */
  async query(options: IoCQueryOptions): Promise<IoCResponse> {
    const startTime = Date.now();

    if (!this.isAvailable()) {
      return {
        results: [],
        metadata: {
          provider: this.name,
          timestamp: Date.now(),
          responseTime: Date.now() - startTime,
          fromCache: false,
          error: 'Provider not enabled',
        },
      };
    }

    try {
      // NVD API search by keyword (package name)
      // Note: NVD primarily focuses on software, not npm packages directly
      // We search for CVEs that mention the package name
      const keywordSearch = `keywordSearch=${encodeURIComponent(options.packageName)}`;
      const url = `${this.baseUrl}?${keywordSearch}&resultsPerPage=${options.maxResults || 20}`;

      const response = await providerFetch(url, {
        headers: {
          'Content-Type': 'application/json',
        },
        timeout: this.config.timeout,
      });

      if (!response.ok) {
        if (response.status === 404) {
          return {
            results: [],
            metadata: {
              provider: this.name,
              timestamp: Date.now(),
              responseTime: Date.now() - startTime,
              fromCache: false,
            },
          };
        }

        // Handle rate limit errors gracefully
        if (response.status === 429) {
          throw new Error(`NVD API rate limit exceeded (429). Please wait before retrying.`);
        }

        throw new Error(`NVD API returned status ${response.status}: ${response.statusText}`);
      }

      const data = (await response.json()) as NVDResponse;
      const cves = data.vulnerabilities || [];

      // Convert to IoCResult format
      const results: IoCResult[] = cves
        .map((v) => v.cve)
        .map((cve) => this.convertToIoCResult(cve, options.packageName, options.version))
        .filter((result): result is IoCResult => result !== null);

      return {
        results,
        metadata: {
          provider: this.name,
          timestamp: Date.now(),
          responseTime: Date.now() - startTime,
          fromCache: false,
        },
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      const isRateLimitError =
        errorMessage.includes('429') ||
        errorMessage.includes('rate limit') ||
        errorMessage.includes('Too Many Requests');

      // Log rate limit errors at debug level to reduce noise
      if (isRateLimitError) {
        logger.debug(`Rate limit hit for NVD:${options.packageName}`, { error: errorMessage });
      } else {
        logger.error(`Error querying NVD for ${options.packageName}`, { error: errorMessage });
      }

      return {
        results: [],
        metadata: {
          provider: this.name,
          timestamp: Date.now(),
          responseTime: Date.now() - startTime,
          fromCache: false,
          error: error instanceof Error ? error.message : String(error),
        },
      };
    }
  }

  /**
   * Convert NVD CVE to IoCResult
   */
  private convertToIoCResult(cve: NVDCVE, packageName: string, version?: string): IoCResult | null {
    // Get English description
    const description =
      cve.descriptions.find((d) => d.lang === 'en')?.value ||
      cve.descriptions[0]?.value ||
      'No description available';

    // Extract CVSS score (prefer v3.1, fallback to v3.0, then v2)
    let cvss: CVSSScore | undefined;
    let severity: VulnerabilitySeverity = 'MEDIUM';

    if (cve.metrics?.cvssMetricV31 && cve.metrics.cvssMetricV31.length > 0) {
      const cvssData = cve.metrics.cvssMetricV31[0]?.cvssData;
      if (cvssData) {
        cvss = {
          version: '3.1',
          baseScore: cvssData.baseScore,
          vector: cvssData.vectorString,
        };
        severity = this.mapCVSSSeverity(cvssData.baseSeverity);
      }
    } else if (cve.metrics?.cvssMetricV30 && cve.metrics.cvssMetricV30.length > 0) {
      const cvssData = cve.metrics.cvssMetricV30[0]?.cvssData;
      if (cvssData) {
        cvss = {
          version: '3.0',
          baseScore: cvssData.baseScore,
          vector: cvssData.vectorString,
        };
        severity = this.mapCVSSSeverity(cvssData.baseSeverity);
      }
    } else if (cve.metrics?.cvssMetricV2 && cve.metrics.cvssMetricV2.length > 0) {
      const cvssData = cve.metrics.cvssMetricV2[0]?.cvssData;
      if (cvssData) {
        cvss = {
          version: '2.0',
          baseScore: cvssData.baseScore,
          vector: cvssData.vectorString,
        };
        severity = this.mapCVSSSeverity(cvssData.baseSeverity);
      }
    }

    // Build references
    const references: string[] = [
      `https://nvd.nist.gov/vuln/detail/${cve.id}`,
      `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve.id}`,
    ];

    if (cve.references) {
      cve.references.forEach((ref) => {
        if (!references.includes(ref.url)) {
          references.push(ref.url);
        }
      });
    }

    // Build CVE info
    const cveInfo: CVEInfo = {
      id: cve.id,
      description,
      publishedDate: cve.published,
      modifiedDate: cve.lastModified,
      ...(cvss ? { cvss } : {}),
      references,
    };

    // Check if this CVE is actually related to the package
    // NVD keyword search can return false positives
    const descriptionLower = description.toLowerCase();
    const packageNameLower = packageName.toLowerCase();

    // If package name doesn't appear in description, it might be a false positive
    // But we'll include it anyway and let the user decide
    if (
      !descriptionLower.includes(packageNameLower) &&
      !descriptionLower.includes(packageNameLower.replace('@', '').replace('/', '-'))
    ) {
      // Still include, but mark as potentially unrelated
      logger.debug(`CVE ${cve.id} may not be directly related to package ${packageName}`);
    }

    return {
      packageName,
      version: version || 'unknown',
      vulnerabilityId: cve.id,
      title: cve.id.startsWith('CVE-') ? cve.id : `CVE-${cve.id}`, // Avoid double CVE- prefix
      description,
      severity,
      ...(cvss ? { cvss } : {}),
      cve: cveInfo,
      affectedVersions: 'unknown', // NVD doesn't provide npm version ranges
      source: this.name,
      providerData: {
        vulnStatus: cve.vulnStatus,
        sourceIdentifier: cve.sourceIdentifier,
      },
      publishedDate: cve.published,
      modifiedDate: cve.lastModified,
      references,
    };
  }

  /**
   * Map CVSS severity to our severity levels
   */
  private mapCVSSSeverity(cvssSeverity: string | undefined): VulnerabilitySeverity {
    if (!cvssSeverity) return 'MEDIUM';
    const upper = cvssSeverity.toUpperCase();
    if (upper === 'CRITICAL') return 'CRITICAL';
    if (upper === 'HIGH') return 'HIGH';
    if (upper === 'MEDIUM' || upper === 'MODERATE') return 'MEDIUM';
    if (upper === 'LOW') return 'LOW';
    return 'MEDIUM'; // Default
  }
}

/**
 * Default CVE provider configuration
 */
export const defaultCVEConfig: IoCProviderConfig = {
  enabled: true, // NVD API is public
  rateLimit: 50, // 50 requests per 30 seconds (NVD rate limit)
  cacheTTL: 24 * 60 * 60 * 1000, // 24 hours (CVE data changes less frequently)
  timeout: 15000, // 15 seconds
  maxRetries: 3,
  retryDelay: 2000, // 2 seconds (NVD recommends longer delays)
};

/**
 * Create CVE provider factory
 */
export function createCVEProvider(config: Partial<IoCProviderConfig> = {}): IoCProvider {
  const apiKey = config.apiKey || process.env['NVD_API_KEY'];
  const finalConfig: IoCProviderConfig = {
    ...defaultCVEConfig,
    ...config,
    ...(apiKey ? { apiKey } : {}),
  };

  return new CVEProvider(finalConfig);
}
