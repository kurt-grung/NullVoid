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
        versionStartIncluding?: string;
        versionStartExcluding?: string;
        versionEndIncluding?: string;
        versionEndExcluding?: string;
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

    // Filter false positives: NVD keyword search matches substrings
    // e.g. "commander" -> "Total Commander", "glob" -> "uses glob to generate"
    const packageNameLower = packageName.toLowerCase();
    const packageNorm = packageNameLower.replace(/^@/, '').replace(/\//g, '-');

    // Prefer CPE: if CPE exists, require package to appear as product/vendor
    const configs = cve.configurations?.flatMap((cfg) => cfg.nodes ?? []) ?? [];
    const allCriteria = configs.flatMap(
      (n) => n.cpeMatch?.map((m: { criteria: string }) => m.criteria) ?? []
    );
    const hasMatchingCpe = allCriteria.some(
      (c: string) =>
        c.toLowerCase().includes(`:${packageNameLower}:`) ||
        c.toLowerCase().includes(`:${packageNorm}:`)
    );

    if (!hasMatchingCpe) {
      const descriptionLower = description.toLowerCase();
      const inDesc =
        descriptionLower.includes(packageNameLower) || descriptionLower.includes(packageNorm);
      if (!inDesc) {
        logger.debug(`CVE ${cve.id} excluded: package "${packageName}" not in description`);
        return null;
      }
      // Exclude common-word false positives: "glob", "tar", "commander" (Total Commander, Midnight Commander), "husky" (HUSKY RTU/WordPress)
      const commonWords = ['glob', 'tar', 'run', 'link', 'node', 'commander', 'husky'];
      if (commonWords.includes(packageNameLower)) {
        // Explicit exclusion: "Midnight Commander" and "Total Commander" are different products from npm commander
        if (
          packageNameLower === 'commander' &&
          (descriptionLower.includes('midnight commander') ||
            descriptionLower.includes('total commander'))
        ) {
          logger.debug(
            `CVE ${cve.id} excluded: "${packageName}" matches different product (Midnight/Total Commander)`
          );
          return null;
        }
        // Require product-like mention (e.g. "glob package", "Axios up to")
        const productLike =
          new RegExp(`\\b${packageNameLower}\\s+(package|up to|before|through|version)`, 'i').test(
            description
          ) || new RegExp(`(package|npm)\\s+${packageNameLower}\\b`, 'i').test(description);
        if (!productLike) {
          logger.debug(
            `CVE ${cve.id} excluded: "${packageName}" likely common-word false positive`
          );
          return null;
        }
      }
    }

    // js-yaml: CVEs about grunt/shiba using js-yaml unsafely, not js-yaml itself (run for all, not just commonWords)
    const desc = description.toLowerCase();
    if (
      packageNameLower === 'js-yaml' &&
      (desc.includes('package grunt') ||
        desc.includes('package shiba') ||
        desc.includes('grunt.file.readyaml') ||
        desc.includes('of package shiba'))
    ) {
      logger.debug(`CVE ${cve.id} excluded: "${packageName}" CVE targets grunt/shiba, not js-yaml`);
      return null;
    }

    // Version-aware filtering: if we have package version and CPE version range, exclude when not affected
    if (version && version !== 'unknown') {
      const isVersionAffected = this.isVersionAffectedByCve(cve, version);
      if (!isVersionAffected) {
        logger.debug(`CVE ${cve.id} excluded: package version ${version} not in affected range`);
        return null;
      }
      // Fallback: parse "fixed in X" / "prior to X" from description when NVD has no CPE version bounds
      const fixedIn = this.parseFixedVersionFromDescription(description);
      if (fixedIn && this.compareVersions(version, fixedIn) >= 0) {
        logger.debug(
          `CVE ${cve.id} excluded: package version ${version} >= fixed version ${fixedIn}`
        );
        return null;
      }
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
   * Check if package version falls within CVE's affected range (from NVD CPE match)
   * Returns true if affected or if version range cannot be determined (conservative)
   */
  private isVersionAffectedByCve(cve: NVDCVE, version: string): boolean {
    const configs = cve.configurations?.flatMap((cfg) => cfg.nodes ?? []) ?? [];
    const allMatches = configs.flatMap((n) => n.cpeMatch ?? []).filter((m) => m.vulnerable);

    if (allMatches.length === 0) return true; // No version info, assume affected

    // If any match has no version bounds, assume affected
    const matchesWithBounds = allMatches.filter(
      (m) =>
        m.versionStartIncluding ||
        m.versionStartExcluding ||
        m.versionEndIncluding ||
        m.versionEndExcluding
    );
    if (matchesWithBounds.length === 0) return true;

    // Version is not affected only if ALL matches with bounds exclude it
    for (const match of matchesWithBounds) {
      if (this.isVersionInCpeRange(version, match)) return true;
    }
    return false;
  }

  private isVersionInCpeRange(
    version: string,
    match: {
      versionStartIncluding?: string;
      versionStartExcluding?: string;
      versionEndIncluding?: string;
      versionEndExcluding?: string;
    }
  ): boolean {
    try {
      if (
        match.versionStartIncluding &&
        this.compareVersions(version, match.versionStartIncluding) < 0
      )
        return false;
      if (
        match.versionStartExcluding &&
        this.compareVersions(version, match.versionStartExcluding) <= 0
      )
        return false;
      if (match.versionEndIncluding && this.compareVersions(version, match.versionEndIncluding) > 0)
        return false;
      if (
        match.versionEndExcluding &&
        this.compareVersions(version, match.versionEndExcluding) >= 0
      )
        return false;
      return true;
    } catch {
      return true; // Default to affected if we can't parse
    }
  }

  /**
   * Parse "fixed in X" or "prior to X" from CVE description when NVD lacks CPE version bounds
   */
  private parseFixedVersionFromDescription(description: string): string | null {
    // "fixed in 1.13.5", "fixed in v1.13.5", "versions 0.30.2 and 1.12.0 contain a patch"
    const fixedInMatch = description.match(
      /(?:fixed in|patched in|resolved in)\s+(?:v)?(\d+\.\d+\.\d+)/i
    );
    if (fixedInMatch?.[1]) return fixedInMatch[1];
    const priorToMatch = description.match(/prior to\s+(?:v)?(\d+\.\d+\.\d+)/i);
    if (priorToMatch?.[1]) return priorToMatch[1];
    return null;
  }

  private compareVersions(v1: string, v2: string): number {
    const parts1 = v1.split('.').map(Number);
    const parts2 = v2.split('.').map(Number);
    const maxLength = Math.max(parts1.length, parts2.length);
    for (let i = 0; i < maxLength; i++) {
      const part1 = parts1[i] || 0;
      const part2 = parts2[i] || 0;
      if (part1 > part2) return 1;
      if (part1 < part2) return -1;
    }
    return 0;
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
