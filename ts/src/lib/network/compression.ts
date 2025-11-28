/**
 * Compression Support
 * Gzip/Brotli compression for API responses
 */

import type {
  CompressionConfig,
  CompressionAlgorithm,
  CompressionResult
} from '../../types/network-types';
import { NETWORK_OPTIMIZATION_CONFIG } from '../config';
import { logger } from '../logger';
import * as zlib from 'zlib';
import { promisify } from 'util';

const gzip = promisify(zlib.gzip);
const gunzip = promisify(zlib.gunzip);
const brotliCompress = promisify(zlib.brotliCompress);
const brotliDecompress = promisify(zlib.brotliDecompress);
const deflate = promisify(zlib.deflate);
const inflate = promisify(zlib.inflate);

/**
 * Compression manager
 */
export class CompressionManager {
  private config: CompressionConfig;
  
  constructor(config?: Partial<CompressionConfig>) {
    this.config = {
      ...NETWORK_OPTIMIZATION_CONFIG.COMPRESSION,
      ...config,
      algorithms: config?.algorithms || NETWORK_OPTIMIZATION_CONFIG.COMPRESSION.algorithms
    } as CompressionConfig;
  }
  
  /**
   * Compress data
   */
  async compress(
    data: string | Buffer,
    algorithm?: CompressionAlgorithm
  ): Promise<CompressionResult> {
    if (!this.config.enabled) {
      const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data);
      return {
        originalSize: buffer.length,
        compressedSize: buffer.length,
        ratio: 1,
        algorithm: 'gzip',
        compressionTime: 0
      };
    }
    
    const startTime = Date.now();
    const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data);
    const originalSize = buffer.length;
    
    // Skip compression if data is too small
    if (originalSize < this.config.minSize) {
      return {
        originalSize,
        compressedSize: originalSize,
        ratio: 1,
        algorithm: 'gzip',
        compressionTime: Date.now() - startTime
      };
    }
    
    // Determine algorithm
    const algo = algorithm || this.config.algorithms[0] || 'gzip';
    
    let compressed: Buffer;
    try {
      switch (algo) {
        case 'gzip':
          compressed = await gzip(buffer, { level: this.config.level });
          break;
        case 'brotli':
          compressed = await brotliCompress(buffer, {
            params: {
              [zlib.constants.BROTLI_PARAM_QUALITY]: this.config.level
            }
          });
          break;
        case 'deflate':
          compressed = await deflate(buffer, { level: this.config.level });
          break;
        default:
          compressed = buffer;
      }
    } catch (error) {
      logger.warn(`Compression failed with ${algo}, using uncompressed`, { error: error instanceof Error ? error.message : String(error) });
      compressed = buffer;
    }
    
    const compressionTime = Date.now() - startTime;
    const compressedSize = compressed.length;
    const ratio = originalSize > 0 ? compressedSize / originalSize : 1;
    
    return {
      originalSize,
      compressedSize,
      ratio,
      algorithm: algo,
      compressionTime
    };
  }
  
  /**
   * Decompress data
   */
  async decompress(
    data: Buffer,
    algorithm: CompressionAlgorithm
  ): Promise<Buffer> {
    if (!this.config.enabled) {
      return data;
    }
    
    try {
      switch (algorithm) {
        case 'gzip':
          return await gunzip(data);
        case 'brotli':
          return await brotliDecompress(data);
        case 'deflate':
          return await inflate(data);
        default:
          return data;
      }
    } catch (error) {
      logger.warn(`Decompression failed with ${algorithm}`, { error: error instanceof Error ? error.message : String(error) });
      throw error;
    }
  }
  
  /**
   * Get Accept-Encoding header value
   */
  getAcceptEncodingHeader(): string {
    if (!this.config.enabled) {
      return 'identity';
    }
    
    const encodings: string[] = [];
    
    if (this.config.algorithms.includes('brotli')) {
      encodings.push('br');
    }
    if (this.config.algorithms.includes('gzip')) {
      encodings.push('gzip');
    }
    if (this.config.algorithms.includes('deflate')) {
      encodings.push('deflate');
    }
    
    return encodings.length > 0 ? encodings.join(', ') : 'identity';
  }
  
  /**
   * Parse Content-Encoding header and determine algorithm
   */
  parseContentEncoding(header: string | null | undefined): CompressionAlgorithm | null {
    if (!header) {
      return null;
    }
    
    const encoding = header.toLowerCase().trim();
    
    if (encoding.includes('br') || encoding.includes('brotli')) {
      return 'brotli';
    }
    if (encoding.includes('gzip')) {
      return 'gzip';
    }
    if (encoding.includes('deflate')) {
      return 'deflate';
    }
    
    return null;
  }
  
  /**
   * Check if compression is beneficial
   */
  isCompressionBeneficial(result: CompressionResult): boolean {
    // Compression is beneficial if ratio < 0.9 (10% or more reduction)
    return result.ratio < 0.9;
  }
}

/**
 * Global compression manager instance
 */
let globalCompressionManager: CompressionManager | null = null;

/**
 * Get or create global compression manager
 */
export function getCompressionManager(config?: Partial<CompressionConfig>): CompressionManager {
  if (!globalCompressionManager) {
    globalCompressionManager = new CompressionManager(config);
  }
  return globalCompressionManager;
}

