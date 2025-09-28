/**
 * Configuration-specific type definitions
 */

export interface ScanConfig {
  /** Maximum file size to scan */
  maxFileSize: number;
  /** Maximum scan timeout */
  maxTimeout: number;
  /** Enable sandbox analysis */
  enableSandbox: boolean;
  /** Sandbox timeout */
  sandboxTimeout: number;
  /** Maximum memory usage */
  maxMemory: number;
  /** Enable parallel processing */
  enableParallel: boolean;
  /** Maximum parallel workers */
  maxWorkers: number;
}

export interface SecurityConfig {
  /** Allowed file extensions */
  allowedExtensions: string[];
  /** Blocked file patterns */
  blockedPatterns: string[];
  /** Suspicious patterns */
  suspiciousPatterns: string[];
  /** Dangerous functions */
  dangerousFunctions: string[];
  /** Network patterns */
  networkPatterns: string[];
  /** File system patterns */
  fileSystemPatterns: string[];
}

export interface PerformanceConfig {
  /** Cache TTL in milliseconds */
  cacheTtl: number;
  /** Maximum cache size */
  maxCacheSize: number;
  /** Rate limiting */
  rateLimit: {
    requests: number;
    window: number;
  };
  /** Timeout configurations */
  timeouts: {
    network: number;
    file: number;
    analysis: number;
  };
}
