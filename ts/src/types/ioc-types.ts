/**
 * IoC (Indicators of Compromise) Integration Type Definitions
 * Standardized types for vulnerability data from various providers
 */

/**
 * Severity levels for vulnerabilities
 */
export type VulnerabilitySeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

/**
 * CVSS score information
 */
export interface CVSSScore {
  version: string;
  baseScore: number;
  temporalScore?: number;
  environmentalScore?: number;
  vector: string;
}

/**
 * CVE information
 */
export interface CVEInfo {
  id: string;
  description: string;
  publishedDate: string;
  modifiedDate: string;
  cvss?: CVSSScore;
  references: string[];
}

/**
 * Standardized IoC result from any provider
 */
export interface IoCResult {
  /** Package name */
  packageName: string;
  /** Package version */
  version: string;
  /** Vulnerability ID (CVE, GHSA, etc.) */
  vulnerabilityId: string;
  /** Vulnerability title */
  title: string;
  /** Vulnerability description */
  description: string;
  /** Severity level */
  severity: VulnerabilitySeverity;
  /** CVSS score if available */
  cvss?: CVSSScore | undefined;
  /** CVE information if available */
  cve?: CVEInfo | undefined;
  /** Affected versions range */
  affectedVersions: string;
  /** Fixed versions (if any) */
  fixedVersions?: string[];
  /** Source provider name */
  source: IoCProviderName;
  /** Provider-specific data */
  providerData?: Record<string, unknown>;
  /** First published date */
  publishedDate: string;
  /** Last modified date */
  modifiedDate: string;
  /** References/links */
  references: string[];
}

/**
 * IoC provider names
 */
export type IoCProviderName = 'snyk' | 'npm' | 'ghsa' | 'cve' | 'nvd';

/**
 * Provider configuration
 */
export interface IoCProviderConfig {
  /** Whether provider is enabled */
  enabled: boolean;
  /** API key or token (if required) */
  apiKey?: string;
  /** Rate limit (requests per minute) */
  rateLimit: number;
  /** Cache TTL in milliseconds */
  cacheTTL: number;
  /** Request timeout in milliseconds */
  timeout: number;
  /** Maximum retry attempts */
  maxRetries: number;
  /** Retry delay in milliseconds */
  retryDelay: number;
}

/**
 * Provider query options
 */
export interface IoCQueryOptions {
  /** Package name */
  packageName: string;
  /** Package version (optional, defaults to latest) */
  version?: string;
  /** Include historical data */
  includeHistory?: boolean;
  /** Maximum results to return */
  maxResults?: number;
}

/**
 * Provider response metadata
 */
export interface IoCResponseMetadata {
  /** Provider name */
  provider: IoCProviderName;
  /** Query timestamp */
  timestamp: number;
  /** Response time in milliseconds */
  responseTime: number;
  /** Whether result was from cache */
  fromCache: boolean;
  /** Error information if any */
  error?: string;
}

/**
 * Complete IoC response
 */
export interface IoCResponse {
  /** Results */
  results: IoCResult[];
  /** Metadata */
  metadata: IoCResponseMetadata;
}

/**
 * Base interface for all IoC providers
 */
export interface IoCProvider {
  /** Provider name */
  readonly name: IoCProviderName;
  /** Provider configuration */
  readonly config: IoCProviderConfig;

  /**
   * Query vulnerabilities for a package
   */
  query(options: IoCQueryOptions): Promise<IoCResponse>;

  /**
   * Check if provider is available/configured
   */
  isAvailable(): boolean;

  /**
   * Get provider health status
   */
  getHealth(): Promise<{ healthy: boolean; message?: string }>;
}

/**
 * Provider factory function type
 */
export type IoCProviderFactory = (config: IoCProviderConfig) => IoCProvider;

/**
 * Provider registry entry
 */
export interface ProviderRegistryEntry {
  /** Provider name */
  name: IoCProviderName;
  /** Factory function */
  factory: IoCProviderFactory;
  /** Default configuration */
  defaultConfig: IoCProviderConfig;
}

/**
 * Aggregated IoC results from multiple providers
 */
export interface AggregatedIoCResults {
  /** All results grouped by package */
  byPackage: Record<string, IoCResult[]>;
  /** Provider statistics */
  providerStats: Record<
    IoCProviderName,
    {
      queried: boolean;
      success: boolean;
      resultCount: number;
      responseTime: number;
      error?: string;
    }
  >;
  /** Total results count */
  totalResults: number;
  /** Unique vulnerability IDs */
  uniqueVulnerabilities: string[];
}
