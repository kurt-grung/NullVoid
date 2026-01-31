/**
 * Network Optimization Type Definitions
 */

/**
 * Connection pool configuration
 */
export interface ConnectionPoolConfig {
  /** Maximum connections per domain */
  maxConnectionsPerDomain: number;
  /** Keep-alive timeout in milliseconds */
  keepAliveTimeout: number;
  /** Connection timeout in milliseconds */
  connectTimeout: number;
  /** Idle connection timeout in milliseconds */
  idleTimeout: number;
  /** Enable connection pooling */
  enabled: boolean;
}

/**
 * Request batching configuration
 */
export interface RequestBatchingConfig {
  /** Enable request batching */
  enabled: boolean;
  /** Maximum batch size */
  maxBatchSize: number;
  /** Maximum wait time before sending batch (ms) */
  maxWaitTime: number;
  /** Batch timeout in milliseconds */
  batchTimeout: number;
  /** Priority levels */
  priorityLevels: number;
}

/**
 * Compression configuration
 */
export interface CompressionConfig {
  /** Enable compression */
  enabled: boolean;
  /** Supported compression algorithms */
  algorithms: CompressionAlgorithm[];
  /** Minimum size to compress (bytes) */
  minSize: number;
  /** Compression level (1-9) */
  level: number;
}

/**
 * Compression algorithm
 */
export type CompressionAlgorithm = 'gzip' | 'brotli' | 'deflate';

/**
 * CDN configuration
 */
export interface CDNConfig {
  /** Enable CDN */
  enabled: boolean;
  /** CDN base URL */
  baseUrl?: string;
  /** Fallback to origin if CDN fails */
  fallbackToOrigin: boolean;
  /** Cache headers to respect */
  respectCacheHeaders: boolean;
}

/**
 * Network request options
 */
export interface NetworkRequestOptions {
  /** Request timeout in milliseconds */
  timeout: number;
  /** Maximum retries */
  maxRetries: number;
  /** Retry delay in milliseconds */
  retryDelay: number;
  /** Use connection pooling */
  useConnectionPool: boolean;
  /** Use compression */
  useCompression: boolean;
  /** Priority level */
  priority: number;
}

/**
 * Batched request
 */
export interface BatchedRequest<T = unknown> {
  /** Request ID */
  id: string;
  /** Request URL */
  url: string;
  /** Request options */
  options: Partial<NetworkRequestOptions>;
  /** Request function to execute */
  requestFn: () => Promise<T>;
  /** Resolve function */
  resolve: (value: unknown) => void;
  /** Reject function */
  reject: (error: Error) => void;
  /** Timestamp when request was added */
  timestamp: number;
}

/**
 * Request batch
 */
export interface RequestBatch {
  /** Batch ID */
  id: string;
  /** Requests in batch */
  requests: BatchedRequest[];
  /** Batch priority */
  priority: number;
  /** Created timestamp */
  createdAt: number;
}

/**
 * Connection pool statistics
 */
export interface ConnectionPoolStats {
  /** Active connections */
  activeConnections: number;
  /** Idle connections */
  idleConnections: number;
  /** Total connections */
  totalConnections: number;
  /** Connections per domain */
  connectionsPerDomain: Record<string, number>;
  /** Connection errors */
  errors: number;
  /** Connection timeouts */
  timeouts: number;
}

/**
 * Network performance metrics
 */
export interface NetworkMetrics {
  /** Total requests */
  totalRequests: number;
  /** Successful requests */
  successfulRequests: number;
  /** Failed requests */
  failedRequests: number;
  /** Average response time (ms) */
  averageResponseTime: number;
  /** Total bytes sent */
  bytesSent: number;
  /** Total bytes received */
  bytesReceived: number;
  /** Compression ratio */
  compressionRatio: number;
  /** Cache hit rate */
  cacheHitRate: number;
  /** Connection pool utilization */
  poolUtilization: number;
}

/**
 * HTTP connection
 */
export interface HTTPConnection {
  /** Connection ID */
  id: string;
  /** Domain */
  domain: string;
  /** Created timestamp */
  createdAt: number;
  /** Last used timestamp */
  lastUsed: number;
  /** Request count */
  requestCount: number;
  /** Whether connection is active */
  active: boolean;
}

/**
 * Compression result
 */
export interface CompressionResult {
  /** Original size in bytes */
  originalSize: number;
  /** Compressed size in bytes */
  compressedSize: number;
  /** Compression ratio */
  ratio: number;
  /** Algorithm used */
  algorithm: CompressionAlgorithm;
  /** Time taken to compress (ms) */
  compressionTime: number;
}
