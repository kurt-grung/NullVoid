/**
 * Phase 4: IPFS Verification Unit Tests
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import {
  computePackageCID,
  verifyPackageCID,
  fetchFromIPFS,
} from '../../src/lib/ipfsVerification';

describe('IPFS Verification (Phase 4)', () => {
  let tempDir: string;
  let testFilePath: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nullvoid-ipfs-test-'));
    testFilePath = path.join(tempDir, 'test.txt');
    fs.writeFileSync(testFilePath, 'Hello, NullVoid Phase 4!');
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  describe('computePackageCID', () => {
    it('should compute CID for file path', async () => {
      const result = await computePackageCID(testFilePath);
      expect(result).toHaveProperty('cid');
      expect(result).toHaveProperty('algorithm', 'sha2-256');
      expect(result.cid).toMatch(/^b[a-z0-9]+$/);
    });

    it('should compute same CID for same content (buffer)', async () => {
      const buffer = Buffer.from('Hello, NullVoid Phase 4!');
      const result1 = await computePackageCID(testFilePath);
      const result2 = await computePackageCID(buffer);
      expect(result1.cid).toBe(result2.cid);
    });

    it('should compute different CID for different content', async () => {
      const otherPath = path.join(tempDir, 'other.txt');
      fs.writeFileSync(otherPath, 'Different content');
      const result1 = await computePackageCID(testFilePath);
      const result2 = await computePackageCID(otherPath);
      expect(result1.cid).not.toBe(result2.cid);
    });
  });

  describe('verifyPackageCID', () => {
    it('should verify when CID matches', async () => {
      const { cid } = await computePackageCID(testFilePath);
      const result = await verifyPackageCID(testFilePath, cid);
      expect(result.verified).toBe(true);
      expect(result.cid).toBe(cid);
    });

    it('should fail when CID does not match', async () => {
      const result = await verifyPackageCID(testFilePath, 'bafkreifakecid123');
      expect(result.verified).toBe(false);
      expect(result.cid).not.toBe('bafkreifakecid123');
    });
  });

  describe('fetchFromIPFS', () => {
    it('should return null for invalid CID (no network)', async () => {
      const result = await fetchFromIPFS('bafkreinvalid', { GATEWAY_URL: 'https://ipfs.io' });
      expect(result).toBeNull();
    });
  });
});
