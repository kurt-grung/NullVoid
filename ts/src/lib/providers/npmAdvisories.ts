/**
 * npm Security Advisories IoC Provider
 * Integration with npm's official security advisories API
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
 * npm Advisory response types
 */
interface NpmAdvisory {
  id: number;
  title: string;
  module_name: string;
  vulnerable_versions: string;
  patched_versions: string;
  overview: string;
  recommendation: string;
  references: string;
  severity: 'critical' | 'high' | 'moderate' | 'low';
  cwe?: string[];
  cves?: string[];
  url: string;
  found_by?: string;
  reported_date?: string;
  published_date?: string;
  updated_date?: string;
}

interface NpmAdvisoriesResponse {
  total: number;
  limit: number;
  offset: number;
  results: NpmAdvisory[];
}

/**
 * npm Security Advisories IoC Provider Implementation
 */
export class NpmAdvisoriesProvider implements IoCProvider {
  readonly name = 'npm' as const;
  readonly config: IoCProviderConfig;
  private readonly baseUrl = 'https://registry.npmjs.org/-/npm/v1/security/advisories';
  
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
      const response = await fetchWithTimeout(`${this.baseUrl}?per_page=1`, {
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
          error: 'Provider not enabled'
        }
      };
    }
    
    try {
      // Query npm advisories API
      // Note: npm API doesn't have a direct package endpoint, so we query all and filter
      const url = `${this.baseUrl}?package=${encodeURIComponent(options.packageName)}`;
      
      const response = await fetchWithTimeout(url, {
        headers: {
          'Content-Type': 'application/json'
        },
        timeout: this.config.timeout
      });
      
      if (!response.ok) {
        if (response.status === 404) {
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
        
        throw new Error(`npm Advisories API returned status ${response.status}: ${response.statusText}`);
      }
      
      const data = await response.json() as NpmAdvisoriesResponse;
      const advisories = data.results || [];
      
      // Filter by version if specified
      let filteredAdvisories = advisories;
      if (options.version) {
        filteredAdvisories = this.filterByVersion(advisories, options.version);
      }
      
      // Limit results if specified
      if (options.maxResults) {
        filteredAdvisories = filteredAdvisories.slice(0, options.maxResults);
      }
      
      // Convert to IoCResult format
      const results: IoCResult[] = filteredAdvisories.map(advisory => 
        this.convertToIoCResult(advisory, options.packageName, options.version)
      );
      
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
      logger.error(`Error querying npm Advisories for ${options.packageName}`, { error: error instanceof Error ? error.message : String(error) });
      
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
   * Filter advisories by version
   */
  private filterByVersion(advisories: NpmAdvisory[], version: string): NpmAdvisory[] {
    return advisories.filter(advisory => {
      // Check if version is in vulnerable range
      if (advisory.vulnerable_versions) {
        return this.isVersionInRange(version, advisory.vulnerable_versions);
      }
      return true; // Include if no version info
    });
  }
  
  /**
   * Check if version is in semver range
   */
  private isVersionInRange(version: string, range: string): boolean {
    try {
      // Handle common npm range patterns
      if (range === '*') return true;
      if (range === '<0.0.0') return false;
      
      // Handle ranges like ">=1.0.0 <2.0.0"
      const rangeParts = range.split(/\s+/);
      for (const part of rangeParts) {
        if (part.startsWith('>=')) {
          const minVersion = part.substring(2).trim();
          if (this.compareVersions(version, minVersion) < 0) return false;
        } else if (part.startsWith('<=')) {
          const maxVersion = part.substring(2).trim();
          if (this.compareVersions(version, maxVersion) > 0) return false;
        } else if (part.startsWith('>')) {
          const minVersion = part.substring(1).trim();
          if (this.compareVersions(version, minVersion) <= 0) return false;
        } else if (part.startsWith('<')) {
          const maxVersion = part.substring(1).trim();
          if (this.compareVersions(version, maxVersion) >= 0) return false;
        }
      }
      return true;
    } catch {
      return true; // Default to include if we can't parse
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
   * Convert npm advisory to IoCResult
   */
  private convertToIoCResult(
    advisory: NpmAdvisory,
    packageName: string,
    version?: string
  ): IoCResult {
    // Map npm severity to our severity levels
    const severityMap: Record<string, VulnerabilitySeverity> = {
      'critical': 'CRITICAL',
      'high': 'HIGH',
      'moderate': 'MEDIUM',
      'low': 'LOW'
    };
    
    const severity = severityMap[advisory.severity] || 'MEDIUM';
    
    // Extract CVE IDs
    const cveIds = advisory.cves || [];
    const vulnerabilityId = cveIds[0] || `npm-${advisory.id}`;
    
    // Build references
    const references: string[] = [advisory.url];
    
    if (advisory.references) {
      // Parse references (can be comma-separated or newline-separated)
      const refs = advisory.references.split(/[,\n]/).map(r => r.trim()).filter(Boolean);
      references.push(...refs);
    }
    
    if (cveIds.length > 0) {
      cveIds.forEach(cve => {
        references.push(`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve}`);
      });
    }
    
    // Build CVE info if available
    const cve: CVEInfo | undefined = cveIds.length > 0 ? {
      id: cveIds[0] || '',
      description: advisory.overview || advisory.recommendation || '',
      publishedDate: advisory.published_date || advisory.reported_date || new Date().toISOString(),
      modifiedDate: advisory.updated_date || advisory.published_date || new Date().toISOString(),
      references
    } : undefined;
    
    // Parse fixed versions
    const fixedVersions = advisory.patched_versions
      ? advisory.patched_versions.split(',').map(v => v.trim()).filter(Boolean)
      : undefined;
    
    return {
      packageName,
      version: version || 'unknown',
      vulnerabilityId,
      title: advisory.title,
      description: advisory.overview || advisory.recommendation || '',
      severity,
      ...(cve ? { cve } : {}),
      affectedVersions: advisory.vulnerable_versions,
      ...(fixedVersions ? { fixedVersions } : {}),
      source: this.name,
      providerData: {
        advisoryId: advisory.id,
        cwe: advisory.cwe,
        foundBy: advisory.found_by
      },
      publishedDate: advisory.published_date || advisory.reported_date || new Date().toISOString(),
      modifiedDate: advisory.updated_date || advisory.published_date || new Date().toISOString(),
      references
    };
  }
}

/**
 * Default npm Advisories provider configuration
 */
export const defaultNpmAdvisoriesConfig: IoCProviderConfig = {
  enabled: true, // npm advisories are public, no API key needed
  rateLimit: 100, // 100 requests per minute
  cacheTTL: 60 * 60 * 1000, // 1 hour
  timeout: 10000, // 10 seconds
  maxRetries: 3,
  retryDelay: 1000 // 1 second
};

/**
 * Create npm Advisories provider factory
 */
export function createNpmAdvisoriesProvider(config: Partial<IoCProviderConfig> = {}): IoCProvider {
  const finalConfig: IoCProviderConfig = {
    ...defaultNpmAdvisoriesConfig,
    ...config
  };
  
  return new NpmAdvisoriesProvider(finalConfig);
}

