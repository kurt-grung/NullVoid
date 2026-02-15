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
  /** Enable IoC (Indicators of Compromise) provider queries */
  iocEnabled?: boolean;
  /** Comma-separated list of IoC providers to use (snyk,npm,ghsa,cve) */
  iocProviders?: string;
  /** Enable dependency confusion analysis (default: true) */
  dependencyConfusionEnabled?: boolean;
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
  | 'DEPENDENCY_CONFUSION_TIMELINE'
  | 'DEPENDENCY_CONFUSION_SUSPICIOUS_NAME'
  | 'DEPENDENCY_CONFUSION_SCOPE'
  | 'DEPENDENCY_CONFUSION_GIT_ACTIVITY'
  | 'SANDBOX_EXECUTION_ERROR'
  | 'SANDBOX_TIMEOUT'
  | 'SANDBOX_MEMORY_LIMIT'
  | 'SANDBOX_SECURITY_VIOLATION'
  | 'PATH_VALIDATION_ERROR'
  | 'VALIDATION_ERROR'
  | 'SECURITY_ERROR'
  | 'MALICIOUS_CODE_ERROR'
  | 'INPUT_VALIDATION_ERROR'
  | 'ERROR_HANDLING_FAILURE'
  | 'PARALLEL_PROCESSING_ERROR'
  | 'PARALLEL_FILE_ANALYSIS_ERROR'
  | 'FILE_ACCESS_ERROR'
  | 'FILE_ANALYSIS_ERROR'
  | 'SUSPICIOUS_FILE_SIZE'
  | 'SUSPICIOUS_FILE_TYPE'
  | 'DEPENDENCY_CONFUSION'
  | 'DEPENDENCY_CONFUSION_ERROR'
  | 'DEPENDENCY_CONFUSION_TIMELINE'
  | 'DEPENDENCY_CONFUSION_PATTERN'
  | 'DEPENDENCY_CONFUSION_SCOPE'
  | 'DEPENDENCY_CONFUSION_ACTIVITY'
  | 'DEPENDENCY_CONFUSION_ML_ANOMALY'
  | 'DEPENDENCY_CONFUSION_PREDICTIVE_RISK'
  | 'TIMEOUT_EXCEEDED'
  | 'MODULE_LOADING_ATTEMPT'
  | 'CODE_GENERATION_ATTEMPT'
  | 'EXECUTION_TIMEOUT'
  | 'MEMORY_EXHAUSTION'
  | 'WALLET_ETHEREUMHIJACK'
  | 'WALLET_TRANSACTIONREDIRECT'
  | 'WALLET_ADDRESSSWAP'
  | 'WALLET_MULTICHAIN'
  | 'WALLET_OBFUSCATION'
  | 'WALLET_NETWORKHOOKS'
  | 'OBFUSCATED_WALLET_CODE'
  | 'FILE_ANALYSIS_ERROR'
  | 'PATH_TRAVERSAL_ATTEMPT'
  | 'MALICIOUS_CODE_STRUCTURE'
  | 'SUSPICIOUS_FILE'
  | 'SUSPICIOUS_DEPENDENCY'
  | 'NLP_SECURITY_INDICATOR'
  | 'PACKAGE_NOT_FOUND'
  | 'SCAN_ERROR'
  | 'ANALYSIS_ERROR'
  | 'SECURITY_ERROR'
  | 'VALIDATION_ERROR'
  | 'UNKNOWN_ERROR'
  | 'VULNERABLE_PACKAGE'
  | 'SUSPICIOUS_PACKAGE_NAME'
  | 'TYPOSQUATTING_RISK';

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
  /** Allow additional properties for extended threat information */
  [key: string]: unknown;
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
    lineNumber?: number | undefined;
    sampleCode?: string | undefined;
    confidence?: number | undefined;
    metadata?: Record<string, unknown> | undefined;
    package?: string | undefined;
    [key: string]: unknown; // Allow additional properties
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
    package: options.package,
    ...options, // Spread additional properties
  };
}
