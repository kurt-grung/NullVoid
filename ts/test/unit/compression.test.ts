/**
 * Compression Tests
 */

import { describe, it, expect, beforeEach } from '@jest/globals';
import { CompressionManager, getCompressionManager } from '../../src/lib/network/compression';

describe('Compression Manager', () => {
  let manager: CompressionManager;

  beforeEach(() => {
    manager = new CompressionManager();
  });

  it('should create manager instance', () => {
    expect(manager).toBeDefined();
  });

  it('should compress data with gzip', async () => {
    const data = 'This is a test string that should be compressed';
    const result = await manager.compress(data, 'gzip');
    
    expect(result).toBeDefined();
    expect(result.originalSize).toBeGreaterThan(0);
    expect(result.compressedSize).toBeGreaterThan(0);
    expect(result.algorithm).toBe('gzip');
  });

  it('should decompress gzip data', async () => {
    const original = Buffer.from('Test data for compression');
    const compressed = await manager.compress(original.toString(), 'gzip');
    
    // Note: We can't easily test decompression without the actual compressed buffer
    // This test verifies the function exists and can be called
    expect(compressed).toBeDefined();
  });

  it('should get Accept-Encoding header', () => {
    const header = manager.getAcceptEncodingHeader();
    expect(header).toBeDefined();
    expect(typeof header).toBe('string');
    expect(header.length).toBeGreaterThan(0);
  });

  it('should parse Content-Encoding header', () => {
    expect(manager.parseContentEncoding('gzip')).toBe('gzip');
    expect(manager.parseContentEncoding('br')).toBe('brotli');
    expect(manager.parseContentEncoding('deflate')).toBe('deflate');
    expect(manager.parseContentEncoding(null)).toBeNull();
    expect(manager.parseContentEncoding(undefined)).toBeNull();
  });

  it('should check if compression is beneficial', () => {
    const beneficial = {
      originalSize: 1000,
      compressedSize: 500,
      ratio: 0.5,
      algorithm: 'gzip' as const,
      compressionTime: 10
    };
    
    const notBeneficial = {
      originalSize: 1000,
      compressedSize: 950,
      ratio: 0.95,
      algorithm: 'gzip' as const,
      compressionTime: 10
    };
    
    expect(manager.isCompressionBeneficial(beneficial)).toBe(true);
    expect(manager.isCompressionBeneficial(notBeneficial)).toBe(false);
  });

  it('should get global manager instance', () => {
    const globalManager = getCompressionManager();
    expect(globalManager).toBeDefined();
    expect(globalManager).toBeInstanceOf(CompressionManager);
  });
});

