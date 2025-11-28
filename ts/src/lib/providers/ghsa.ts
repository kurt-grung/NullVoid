/**
 * GitHub Security Advisories (GHSA) IoC Provider
 * Integration with GitHub's Security Advisories GraphQL API
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
 * GHSA GraphQL response types
 */
interface GHSAVulnerability {
  ghsaId: string;
  summary: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MODERATE' | 'LOW';
  identifiers: Array<{
    type: string;
    value: string;
  }>;
  publishedAt: string;
  updatedAt: string;
  permalink: string;
  cvss?: {
    score: number;
    vectorString: string;
  };
  cwes?: {
    nodes: Array<{
      cweId: string;
      name: string;
    }>;
  };
  vulnerabilities: {
    nodes: Array<{
      package: {
        name: string;
        ecosystem: string;
      };
      vulnerableVersionRange: string;
      firstPatchedVersion?: {
        identifier: string;
      };
    }>;
  };
}

interface GHSAGraphQLResponse {
  data?: {
    securityAdvisories?: {
      nodes: GHSAVulnerability[];
      pageInfo?: {
        hasNextPage: boolean;
        endCursor?: string;
      };
    };
  };
  errors?: Array<{
    message: string;
    type?: string;
  }>;
}

/**
 * GitHub Security Advisories IoC Provider Implementation
 */
export class GHSAProvider implements IoCProvider {
  readonly name = 'ghsa' as const;
  readonly config: IoCProviderConfig;
  private readonly graphqlUrl = 'https://api.github.com/graphql';
  
  constructor(config: IoCProviderConfig) {
    this.config = config;
  }
  
  /**
   * Check if provider is available
   */
  isAvailable(): boolean {
    // GHSA API can work without auth for public data, but rate limits are lower
    return this.config.enabled;
  }
  
  /**
   * Get provider health status
   */
  async getHealth(): Promise<{ healthy: boolean; message?: string }> {
    try {
      const query = `
        query {
          rateLimit {
            remaining
            resetAt
          }
        }
      `;
      
      const response = await this.makeGraphQLRequest(query);
      
      if (response.data) {
        return { healthy: true };
      } else {
        return { healthy: false, message: 'GraphQL API error' };
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
      // GraphQL query for security advisories
      const query = `
        query($packageName: String!, $first: Int!) {
          securityAdvisories(
            package: $packageName
            ecosystem: NPM
            first: $first
            orderBy: {field: UPDATED_AT, direction: DESC}
          ) {
            nodes {
              ghsaId
              summary
              description
              severity
              identifiers {
                type
                value
              }
              publishedAt
              updatedAt
              permalink
              cvss {
                score
                vectorString
              }
              cwes {
                nodes {
                  cweId
                  name
                }
              }
              vulnerabilities(first: 100) {
                nodes {
                  package {
                    name
                    ecosystem
                  }
                  vulnerableVersionRange
                  firstPatchedVersion {
                    identifier
                  }
                }
              }
            }
            pageInfo {
              hasNextPage
              endCursor
            }
          }
        }
      `;
      
      const variables = {
        packageName: options.packageName,
        first: options.maxResults || 50
      };
      
      const response = await this.makeGraphQLRequest(query, variables);
      
      if (response.errors) {
        throw new Error(`GraphQL errors: ${response.errors.map(e => e.message).join(', ')}`);
      }
      
      const advisories = response.data?.securityAdvisories?.nodes || [];
      
      // Filter by version if specified
      let filteredAdvisories = advisories;
      if (options.version) {
        filteredAdvisories = this.filterByVersion(advisories, options.version);
      }
      
      // Convert to IoCResult format
      const results: IoCResult[] = filteredAdvisories.flatMap(advisory =>
        this.convertToIoCResults(advisory, options.packageName, options.version)
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
      const errorMessage = error instanceof Error ? error.message : String(error);
      const isRateLimitError = errorMessage.includes('403') || 
                               errorMessage.includes('rate limit') ||
                               errorMessage.includes('Rate limit');
      
      // Log rate limit errors at debug level to reduce noise
      if (isRateLimitError) {
        logger.debug(`Rate limit hit for GHSA:${options.packageName}`, { error: errorMessage });
      } else {
        logger.error(`Error querying GHSA for ${options.packageName}`, { error: errorMessage });
      }
      
      return {
        results: [],
        metadata: {
          provider: this.name,
          timestamp: Date.now(),
          responseTime: Date.now() - startTime,
          fromCache: false,
          error: errorMessage
        }
      };
    }
  }
  
  /**
   * Make GraphQL request to GitHub API
   */
  private async makeGraphQLRequest(
    query: string,
    variables?: Record<string, unknown>
  ): Promise<GHSAGraphQLResponse> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json'
    };
    
    // Add auth token if available
    if (this.config.apiKey) {
      headers['Authorization'] = `Bearer ${this.config.apiKey}`;
    }
    
    const response = await fetchWithTimeout(this.graphqlUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        query,
        variables: variables || {}
      }),
      timeout: this.config.timeout
    });
    
    if (!response.ok) {
      // Handle rate limit errors specifically
      if (response.status === 403) {
        throw new Error(`GitHub API returned status 403: rate limit exceeded`);
      }
      throw new Error(`GitHub API returned status ${response.status}: ${response.statusText}`);
    }
    
    return await response.json() as GHSAGraphQLResponse;
  }
  
  /**
   * Filter advisories by version
   */
  private filterByVersion(advisories: GHSAVulnerability[], version: string): GHSAVulnerability[] {
    return advisories.filter(advisory => {
      // Check if any vulnerability node matches the package and version
      return advisory.vulnerabilities.nodes.some(vuln => {
        if (vuln.package.name !== advisory.vulnerabilities.nodes[0]?.package.name) {
          return false;
        }
        
        // Check if version is in vulnerable range
        if (vuln.vulnerableVersionRange) {
          return this.isVersionInRange(version, vuln.vulnerableVersionRange);
        }
        return true;
      });
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
   * Convert GHSA advisory to IoCResults (one per vulnerability node)
   */
  private convertToIoCResults(
    advisory: GHSAVulnerability,
    _packageName: string,
    version?: string
  ): IoCResult[] {
    const results: IoCResult[] = [];
    
    // Map GHSA severity to our severity levels
    const severityMap: Record<string, VulnerabilitySeverity> = {
      'CRITICAL': 'CRITICAL',
      'HIGH': 'HIGH',
      'MODERATE': 'MEDIUM',
      'LOW': 'LOW'
    };
    
    const severity = severityMap[advisory.severity] || 'MEDIUM';
    
    // Extract CVE IDs
    const cveIds = advisory.identifiers
      .filter(id => id.type === 'CVE')
      .map(id => id.value);
    
    const vulnerabilityId = cveIds[0] || advisory.ghsaId;
    
    // Build references
    const references: string[] = [advisory.permalink];
    
    if (cveIds.length > 0) {
      cveIds.forEach(cve => {
        references.push(`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve}`);
        references.push(`https://nvd.nist.gov/vuln/detail/${cve}`);
      });
    }
    
    // Build CVSS score if available
    const cvss = advisory.cvss ? {
      version: '3.1',
      baseScore: advisory.cvss.score,
      vector: advisory.cvss.vectorString
    } : undefined;
    
    // Build CVE info if available
    const cve: CVEInfo | undefined = cveIds.length > 0 ? {
      id: cveIds[0] || '',
      description: advisory.description,
      publishedDate: advisory.publishedAt,
      modifiedDate: advisory.updatedAt,
      ...(cvss ? { cvss } : {}),
      references
    } : undefined;
    
    // Create one result per vulnerability node (package version)
    for (const vuln of advisory.vulnerabilities.nodes) {
      if (vuln.package.ecosystem !== 'NPM') continue;
      
      const fixedVersions = vuln.firstPatchedVersion
        ? [vuln.firstPatchedVersion.identifier]
        : undefined;
      
      results.push({
        packageName: vuln.package.name,
        version: version || 'unknown',
        vulnerabilityId,
        title: advisory.summary,
        description: advisory.description,
        severity,
        ...(cvss ? { cvss } : {}),
        ...(cve ? { cve } : {}),
        affectedVersions: vuln.vulnerableVersionRange,
        ...(fixedVersions ? { fixedVersions } : {}),
        source: this.name,
        providerData: {
          ghsaId: advisory.ghsaId,
          cwes: advisory.cwes?.nodes.map(cwe => cwe.cweId)
        },
        publishedDate: advisory.publishedAt,
        modifiedDate: advisory.updatedAt,
        references
      });
    }
    
    return results;
  }
}

/**
 * Default GHSA provider configuration
 */
export const defaultGHSAConfig: IoCProviderConfig = {
  enabled: true, // GHSA API is public, but auth token increases rate limits
  rateLimit: 60, // 60 requests per hour without auth, 5000/hour with auth
  cacheTTL: 60 * 60 * 1000, // 1 hour
  timeout: 15000, // 15 seconds (GraphQL can be slower)
  maxRetries: 3,
  retryDelay: 1000 // 1 second
};

/**
 * Create GHSA provider factory
 */
export function createGHSAProvider(config: Partial<IoCProviderConfig> = {}): IoCProvider {
  const apiKey = config.apiKey || process.env['GITHUB_TOKEN'];
  const finalConfig: IoCProviderConfig = {
    ...defaultGHSAConfig,
    ...config,
    ...(apiKey ? { apiKey } : {})
  };
  
  return new GHSAProvider(finalConfig);
}

