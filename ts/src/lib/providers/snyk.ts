/**
 * Snyk IoC Provider
 * Integration with Snyk's vulnerability database
 */

import type {
  IoCProvider,
  IoCProviderConfig,
  IoCQueryOptions,
  IoCResponse,
  IoCResult,
  VulnerabilitySeverity,
  CVEInfo
} from '../../types/ioc-types';
import { logger } from '../logger';
import { fetchWithTimeout } from './fetchWithTimeout';

/**
 * Snyk API response types
 */
interface SnykVulnerability {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  cvssScore?: number;
  cveIds?: string[];
  disclosureTime?: string;
  publicationTime?: string;
  identifiers?: {
    CVE?: string[];
    CWE?: string[];
  };
  semver?: {
    vulnerable: string[];
  };
  patched?: string[];
  credit?: string[];
  language: string;
  packageManager: string;
  packageName: string;
  packageVersion?: string;
}

interface SnykApiResponse {
  vulnerabilities?: SnykVulnerability[];
  issues?: SnykVulnerability[];
}

/**
 * Snyk IoC Provider Implementation
 */
export class SnykProvider implements IoCProvider {
  readonly name = 'snyk' as const;
  readonly config: IoCProviderConfig;
  private readonly baseUrl = 'https://api.snyk.io/v1';
  
  constructor(config: IoCProviderConfig) {
    this.config = config;
  }
  
  /**
   * Check if provider is available
   */
  isAvailable(): boolean {
    return this.config.enabled && !!this.config.apiKey;
  }
  
  /**
   * Get provider health status
   */
  async getHealth(): Promise<{ healthy: boolean; message?: string }> {
    if (!this.isAvailable()) {
      return { healthy: false, message: 'Provider not configured (missing API key)' };
    }
    
    try {
      const response = await fetchWithTimeout(`${this.baseUrl}/user/me`, {
        headers: {
          'Authorization': `token ${this.config.apiKey}`,
          'Content-Type': 'application/json'
        },
        timeout: this.config.timeout
      });
      
      if (response.ok) {
        return { healthy: true };
      } else {
        return { healthy: false, message: `API returned status ${response.status}` };
      }
    } catch (error) {
      return {
        healthy: false,
        message: error instanceof Error ? error.message : String(error)
      };
    }
  }
  
  /**
   * Query vulnerabilities for a package
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
          error: 'Provider not available (missing API key)'
        }
      };
    }
    
    try {
      // Snyk API endpoint for npm package vulnerabilities
      const url = `${this.baseUrl}/vuln/npm/${options.packageName}`;
      
      const response = await fetchWithTimeout(url, {
        headers: {
          'Authorization': `token ${this.config.apiKey}`,
          'Content-Type': 'application/json'
        },
        timeout: this.config.timeout
      });
      
      if (!response.ok) {
        if (response.status === 404) {
          // Package not found or no vulnerabilities
          return {
            results: [],
            metadata: {
              provider: this.name,
              timestamp: Date.now(),
              responseTime: Date.now() - startTime,
              fromCache: false
            }
          };
        }
        
        throw new Error(`Snyk API returned status ${response.status}: ${response.statusText}`);
      }
      
      const data = await response.json() as SnykApiResponse;
      const vulnerabilities = data.vulnerabilities || data.issues || [];
      
      // Filter by version if specified
      let filteredVulns = vulnerabilities;
      if (options.version) {
        filteredVulns = this.filterByVersion(vulnerabilities, options.version);
      }
      
      // Limit results if specified
      if (options.maxResults) {
        filteredVulns = filteredVulns.slice(0, options.maxResults);
      }
      
      // Convert to IoCResult format
      const results: IoCResult[] = filteredVulns.map(vuln => this.convertToIoCResult(vuln, options.packageName, options.version));
      
      return {
        results,
        metadata: {
          provider: this.name,
          timestamp: Date.now(),
          responseTime: Date.now() - startTime,
          fromCache: false
        }
      };
    } catch (error) {
      logger.error(`Error querying Snyk for ${options.packageName}`, { error: error instanceof Error ? error.message : String(error) });
      
      return {
        results: [],
        metadata: {
          provider: this.name,
          timestamp: Date.now(),
          responseTime: Date.now() - startTime,
          fromCache: false,
          error: error instanceof Error ? error.message : String(error)
        }
      };
    }
  }
  
  /**
   * Filter vulnerabilities by version
   */
  private filterByVersion(vulnerabilities: SnykVulnerability[], version: string): SnykVulnerability[] {
    return vulnerabilities.filter(vuln => {
      // Check if version is in vulnerable range
      if (vuln.semver?.vulnerable) {
        return vuln.semver.vulnerable.some(range => this.isVersionInRange(version, range));
      }
      return true; // Include if no version info
    });
  }
  
  /**
   * Check if version is in semver range
   */
  private isVersionInRange(version: string, range: string): boolean {
    // Simple semver range checking (can be enhanced with semver library)
    try {
      // Handle common patterns
      if (range === '*') return true;
      if (range.startsWith('>=')) {
        const minVersion = range.substring(2).trim();
        return this.compareVersions(version, minVersion) >= 0;
      }
      if (range.startsWith('<=')) {
        const maxVersion = range.substring(2).trim();
        return this.compareVersions(version, maxVersion) <= 0;
      }
      if (range.includes(' - ')) {
        const [min, max] = range.split(' - ').map(v => v.trim());
        const minVersion = min || '';
        const maxVersion = max || '';
        return this.compareVersions(version, minVersion) >= 0 && this.compareVersions(version, maxVersion) <= 0;
      }
      return true; // Default to include if we can't parse
    } catch {
      return true;
    }
  }
  
  /**
   * Simple version comparison
   */
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
   * Convert Snyk vulnerability to IoCResult
   */
  private convertToIoCResult(
    vuln: SnykVulnerability,
    packageName: string,
    version?: string
  ): IoCResult {
    // Map Snyk severity to our severity levels
    const severityMap: Record<string, VulnerabilitySeverity> = {
      'critical': 'CRITICAL',
      'high': 'HIGH',
      'medium': 'MEDIUM',
      'low': 'LOW'
    };
    
    const severity = severityMap[vuln.severity] || 'MEDIUM';
    
    // Extract CVE IDs
    const cveIds = vuln.cveIds || vuln.identifiers?.CVE || [];
    const vulnerabilityId = cveIds[0] || vuln.id;
    
    // Build affected versions string
    const affectedVersions = vuln.semver?.vulnerable?.join(', ') || 'unknown';
    
    // Build references
    const references: string[] = [
      `https://snyk.io/vuln/${vuln.id}`
    ];
    
    if (cveIds.length > 0) {
      cveIds.forEach(cve => {
        references.push(`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve}`);
      });
    }
    
    // Build CVSS score if available
    const cvss = vuln.cvssScore ? {
      version: '3.1',
      baseScore: vuln.cvssScore,
      vector: ''
    } : undefined;
    
    // Build CVE info if available
    const cve: CVEInfo | undefined = cveIds.length > 0 ? {
      id: cveIds[0] || '',
      description: vuln.description,
      publishedDate: vuln.publicationTime || vuln.disclosureTime || new Date().toISOString(),
      modifiedDate: vuln.disclosureTime || new Date().toISOString(),
      ...(cvss ? { cvss } : {}),
      references
    } : undefined;
    
    return {
      packageName,
      version: version || vuln.packageVersion || 'unknown',
      vulnerabilityId,
      title: vuln.title,
      description: vuln.description,
      severity,
      ...(cvss ? { cvss } : {}),
      ...(cve ? { cve } : {}),
      affectedVersions,
      ...(vuln.patched ? { fixedVersions: vuln.patched } : {}),
      source: this.name,
      providerData: {
        snykId: vuln.id,
        language: vuln.language,
        packageManager: vuln.packageManager,
        credit: vuln.credit
      },
      publishedDate: vuln.publicationTime || vuln.disclosureTime || new Date().toISOString(),
      modifiedDate: vuln.disclosureTime || new Date().toISOString(),
      references
    };
  }
}

/**
 * Default Snyk provider configuration
 */
export const defaultSnykConfig: IoCProviderConfig = {
  enabled: false,
  rateLimit: 60, // 60 requests per minute (Snyk free tier limit)
  cacheTTL: 60 * 60 * 1000, // 1 hour
  timeout: 10000, // 10 seconds
  maxRetries: 3,
  retryDelay: 1000 // 1 second
};

/**
 * Create Snyk provider factory
 */
export function createSnykProvider(config: Partial<IoCProviderConfig> = {}): IoCProvider {
  const apiKey = config.apiKey || process.env['SNYK_API_KEY'];
  const finalConfig: IoCProviderConfig = {
    ...defaultSnykConfig,
    ...config,
    ...(apiKey ? { apiKey } : {})
  };
  
  return new SnykProvider(finalConfig);
}

