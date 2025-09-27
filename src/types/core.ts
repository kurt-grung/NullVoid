/**
 * Core type definitions for NullVoid
 */

// ============================================================================
// SCAN TYPES
// ============================================================================

export interface ScanOptions {
  /** Include all severity levels in results */
  all?: boolean;
  /** Maximum dependency depth to scan */
  maxDepth?: number;
  /** Enable parallel processing */
  parallel?: boolean;
  /** Output format */
  output?: 'json' | 'table' | 'yaml' | 'sarif';
  /** Verbose output */
  verbose?: boolean;
  /** Include test files in scan */
  includeTests?: boolean;
  /** Custom rules file path */
  rules?: string;
  /** Skip signature verification */
  skipSignatures?: boolean;
  /** Custom timeout in milliseconds */
  timeout?: number;
}

export interface ScanResult {
  /** Array of detected threats */
  threats: Threat[];
  /** Number of files scanned */
  filesScanned: number;
  /** Number of packages scanned */
  packagesScanned: number;
  /** Directory structure information */
  directoryStructure?: DirectoryStructure;
  /** Performance metrics */
  performance: PerformanceMetrics;
  /** Scan metadata */
  metadata: ScanMetadata;
}

export interface Threat {
  /** Threat type identifier */
  type: ThreatType;
  /** Human-readable threat message */
  message: string;
  /** Package or file path */
  package: string;
  /** Severity level */
  severity: SeverityLevel;
  /** Detailed threat information */
  details: string;
  /** Line number where threat was found */
  lineNumber?: number;
  /** Sample code snippet */
  sampleCode?: string;
  /** Confidence score (0-1) */
  confidence?: number;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

export type ThreatType = 
  | 'MALICIOUS_CODE_STRUCTURE'
  | 'SUSPICIOUS_MODULE'
  | 'OBFUSCATED_CODE'
  | 'WALLET_HIJACKING'
  | 'NETWORK_MANIPULATION'
  | 'STEALTH_CONTROLS'
  | 'DYNAMIC_REQUIRE'
  | 'ENTROPY_ANALYSIS'
  | 'SIGNATURE_VERIFICATION'
  | 'DEPENDENCY_CONFUSION'
  | 'MODULE_LOADING_ATTEMPT'
  | 'CODE_GENERATION_ATTEMPT'
  | 'EXECUTION_TIMEOUT'
  | 'MEMORY_EXHAUSTION'
  | 'ANALYSIS_ERROR'
  | 'HIGH_DEPENDENCY_COUNT'
  | 'SUSPICIOUS_PACKAGE_NAME'
  | 'DEEP_DEPENDENCY_THREAT'
  | 'TARBALL_ANALYSIS_ERROR'
  | 'SUSPICIOUS_SCRIPT'
  | 'SUSPICIOUS_DESCRIPTION'
  | 'MISSING_REPOSITORY'
  | 'PACKAGE_JSON_ANALYSIS_ERROR'
  | 'SUSPICIOUS_FS_OPERATION'
  | 'PATH_TRAVERSAL'
  | 'FS_CONTEXT_ANALYSIS_ERROR'
  | 'HIGH_ENTROPY_CONTENT'
  | 'ENTROPY_ANALYSIS_ERROR'
  | 'DYNAMIC_CODE_EXECUTION'
  | 'EXTRACTED_FILES_ANALYSIS_ERROR'
  | 'SUSPICIOUS_FILE'
  | 'MALICIOUS_PATTERN'
  | 'CIRCULAR_DEPENDENCY'
  | 'MULTI_CHAIN_TARGETING'
  | 'MISSING_GPG_SIGNATURE'
  | 'INVALID_GPG_SIGNATURE'
  | 'SUSPICIOUS_GPG_KEY'
  | 'GPG_SIGNATURE_ERROR'
  | 'INVALID_INTEGRITY_HASH'
  | 'MISSING_INTEGRITY_HASH'
  | 'MISSING_PACKAGE_JSON_SIGNATURE'
  | 'PACKAGE_SIGNATURE_ERROR'
  | 'MISSING_PACKAGE_FIELD'
  | 'SUSPICIOUS_VERSION'
  | 'PACKAGE_INTEGRITY_ERROR'
  | 'INVALID_TARBALL_SIGNATURE'
  | 'MISSING_TARBALL_SIGNATURE'
  | 'TARBALL_SIGNATURE_ERROR'
  | 'INVALID_PACKAGE_JSON_SIGNATURE'
  | 'PACKAGE_JSON_SIGNATURE_ERROR'
  | 'INCOMPLETE_MAINTAINER_INFO'
  | 'MISSING_MAINTAINER_INFO'
  | 'MAINTAINER_SIGNATURE_ERROR'
  | 'SUSPICIOUS_FILE_CONTENT'
  | 'NODE_MODULES_SCAN_ERROR';

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface DirectoryStructure {
  /** List of directories found */
  directories: string[];
  /** List of files found */
  files: string[];
  /** Total number of directories */
  totalDirectories: number;
  /** Total number of files */
  totalFiles: number;
}

export interface PerformanceMetrics {
  /** Total scan time in milliseconds */
  scanTime: number;
  /** Time spent on static analysis */
  staticAnalysisTime: number;
  /** Time spent on sandbox analysis */
  sandboxAnalysisTime: number;
  /** Memory usage during scan */
  memoryUsage: number;
  /** CPU usage during scan */
  cpuUsage: number;
  /** Number of packages scanned */
  packagesScanned: number;
  /** Number of cache hits */
  cacheHits: number;
  /** Number of cache misses */
  cacheMisses: number;
  /** Cache hit rate (0-1) */
  cacheHitRate: number;
  /** Number of network requests made */
  networkRequests: number;
  /** Number of errors encountered */
  errors: number;
  /** Packages scanned per second */
  packagesPerSecond: number;
  /** Total duration in milliseconds */
  duration: number;
}

export interface ScanMetadata {
  /** Scan start timestamp */
  startTime: Date;
  /** Scan end timestamp */
  endTime: Date;
  /** NullVoid version used */
  version: string;
  /** Node.js version */
  nodeVersion: string;
  /** Operating system */
  platform: string;
  /** Scan target path */
  target: string;
}

// ============================================================================
// UTILITY TYPES
// ============================================================================

export type ProgressCallback = (filePath: string) => void;

export type ThreatCallback = (threat: Threat) => void;

export type ErrorCallback = (error: Error) => void;

export interface CacheEntry<T> {
  data: T;
  timestamp: number;
  ttl: number;
}

export interface RateLimitInfo {
  requests: number;
  window: number;
  remaining: number;
  resetTime: number;
}
