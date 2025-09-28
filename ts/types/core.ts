/**
 * Core type definitions for NullVoid
 */

// ============================================================================
// SCAN TYPES
// ============================================================================

export interface ScanOptions {
  /** Maximum depth for dependency scanning */
  depth?: number;
  /** Enable parallel processing */
  parallel?: boolean;
  /** Number of workers for parallel processing */
  workers?: number | undefined;
  /** Include development dependencies */
  includeDevDependencies?: boolean;
  /** Skip cache */
  skipCache?: boolean;
  /** Output file path */
  outputFile?: string;
  /** Output format */
  format?: 'json' | 'sarif' | 'text';
  /** Enable verbose logging */
  verbose?: boolean;
  /** Enable debug mode */
  debug?: boolean;
  /** Custom rules file */
  rulesFile?: string;
  /** SARIF output file */
  sarifFile?: string;
  /** Output directory */
  output?: string;
  /** Maximum depth */
  maxDepth?: number;
  /** Timeout in milliseconds */
  timeout?: number;
  /** Show all results */
  all?: boolean;
}

export interface ScanResult {
  /** List of detected threats */
  threats: Threat[];
  /** Performance metrics */
  metrics: PerformanceMetrics;
  /** Scan summary */
  summary: {
    totalFiles: number;
    totalPackages: number;
    threatsFound: number;
    scanDuration: number;
  };
  /** Packages scanned */
  packagesScanned?: number;
  /** Files scanned */
  filesScanned?: number;
  /** Performance data */
  performance?: PerformanceMetrics;
  /** Metadata */
  metadata?: Record<string, unknown>;
  /** Directory structure */
  directoryStructure?: DirectoryStructure;
  /** Dependency tree analysis */
  dependencyTree?: {
    totalPackages: number;
    maxDepth: number;
    packagesWithThreats: number;
    deepDependencies: number;
  };
}

export interface PerformanceMetrics {
  /** Total scan duration in milliseconds */
  duration: number;
  /** Memory usage in MB */
  memoryUsage: number;
  /** CPU usage percentage */
  cpuUsage: number;
  /** Files processed per second */
  filesPerSecond: number;
  /** Packages processed per second */
  packagesPerSecond: number;
}

export interface DirectoryStructure {
  /** Directory path */
  path: string;
  /** List of files in directory */
  files: string[];
  /** List of subdirectories */
  directories: string[];
  /** Total file count */
  totalFiles?: number;
  /** Total directory count */
  totalDirectories?: number;
}

export interface DependencyTree {
  /** Package name */
  name: string;
  /** Package version */
  version: string;
  /** Dependencies */
  dependencies: DependencyTree[];
  /** Development dependencies */
  devDependencies: DependencyTree[];
  /** Total dependency count */
  totalDependencies: number;
}

// ============================================================================
// THREAT TYPES
// ============================================================================

export type ThreatType = 
  | 'MALICIOUS_CODE'
  | 'WALLET_HIJACKING'
  | 'NETWORK_MANIPULATION'
  | 'OBFUSCATED_CODE'
  | 'SUSPICIOUS_SCRIPT'
  | 'CRYPTO_MINING'
  | 'SUPPLY_CHAIN_ATTACK'
  | 'DATA_EXFILTRATION'
  | 'PATH_TRAVERSAL'
  | 'COMMAND_INJECTION'
  | 'DYNAMIC_REQUIRE'
  | 'SUSPICIOUS_MODULE'
  | 'OBFUSCATED_IOC'
  | 'DEPENDENCY_CONFUSION'
  | 'DEPENDENCY_CONFUSION_ERROR'
  | 'TIMEOUT_EXCEEDED'
  | 'FILE_ANALYSIS_ERROR'
  | 'PATH_TRAVERSAL_ATTEMPT'
  | 'OBFUSCATED_WALLET_CODE'
  | 'MALICIOUS_CODE_STRUCTURE'
  | 'SUSPICIOUS_FILE'
  | 'SUSPICIOUS_DEPENDENCY'
  | 'PACKAGE_NOT_FOUND'
  | 'SCAN_ERROR'
  | 'ANALYSIS_ERROR';

export type SeverityLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface Threat {
  /** Threat type identifier */
  type: ThreatType;
  /** Human-readable threat message */
  message: string;
  /** Package or file path (legacy) */
  package?: string | undefined;
  /** File path where threat was found */
  filePath: string;
  /** File name */
  filename: string;
  /** Severity level */
  severity: SeverityLevel;
  /** Detailed threat information */
  details: string;
  /** Line number where threat was found */
  lineNumber?: number | undefined;
  /** Sample code snippet */
  sampleCode?: string | undefined;
  /** Confidence score (0-1) */
  confidence?: number | undefined;
  /** Additional metadata */
  metadata?: Record<string, unknown> | undefined;
}

// ============================================================================
// UTILITY TYPES
// ============================================================================

export type ProgressCallback = (progress: {
  current: number;
  total: number;
  message: string;
  packageName?: string;
}) => void;

/**
 * Helper function to create a Threat object with required properties
 */
export function createThreat(
  type: ThreatType,
  message: string,
  filePath: string,
  filename: string,
  severity: SeverityLevel,
  details: string,
  options: {
    lineNumber?: number;
    sampleCode?: string;
    confidence?: number;
    metadata?: Record<string, unknown>;
    package?: string;
  } = {}
): Threat {
  return {
    type,
    message,
    filePath,
    filename,
    severity,
    details,
    lineNumber: options.lineNumber,
    sampleCode: options.sampleCode,
    confidence: options.confidence,
    metadata: options.metadata,
    package: options.package
  };
}