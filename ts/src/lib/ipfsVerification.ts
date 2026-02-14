/**
 * IPFS Content-Addressing for Package Verification
 *
 * Computes CID (Content Identifier) for package tarballs.
 * Enables immutable verification via content hashing.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import axios from 'axios';

// CIDv1 raw (0x55) sha2-256 (0x12): manual construction for CJS/ESM compatibility
const RAW_CODEC = 0x55;
const SHA256_CODE = 0x12;
const SHA256_SIZE = 32;

export interface VerificationResult {
  cid: string;
  algorithm: string;
  verified: boolean;
}

// Base32 encoding (RFC 4648) for CID multibase
const BASE32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';

function base32Encode(data: Uint8Array): string {
  let result = '';
  let bits = 0;
  let value = 0;
  for (let i = 0; i < data.length; i++) {
    const byte = data[i];
    value = (value << 8) | (byte ?? 0);
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      result += BASE32_ALPHABET[(value >>> bits) & 31];
    }
  }
  if (bits > 0) result += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return result;
}

function toUint8Array(buf: Buffer): Uint8Array {
  return new Uint8Array(buf);
}

/**
 * Compute CID (Content Identifier) for a file or buffer.
 * Uses sha2-256 and raw codec (CIDv1).
 */
export async function computePackageCID(
  input: string | Buffer,
  _config?: Partial<{ ALGORITHM: string }>
): Promise<{ cid: string; algorithm: string }> {
  const buffer =
    typeof input === 'string'
      ? fs.readFileSync(path.resolve(input))
      : Buffer.isBuffer(input)
        ? input
        : Buffer.from(input);

  const digest = crypto.createHash('sha256').update(buffer).digest();
  const digestUint = toUint8Array(digest);

  const multihash = new Uint8Array(2 + digestUint.length);
  multihash[0] = SHA256_CODE;
  multihash[1] = SHA256_SIZE;
  multihash.set(digestUint, 2);

  const cidBytes = new Uint8Array(1 + 1 + multihash.length);
  cidBytes[0] = 1;
  cidBytes[1] = RAW_CODEC;
  cidBytes.set(multihash, 2);

  const cidString = 'b' + base32Encode(cidBytes);

  return {
    cid: cidString,
    algorithm: 'sha2-256',
  };
}

/**
 * Verify that a file's computed CID matches the expected CID.
 */
export async function verifyPackageCID(
  tarballPath: string,
  expectedCID: string
): Promise<VerificationResult> {
  const { cid: actualCID } = await computePackageCID(tarballPath);
  const verified = actualCID === expectedCID;
  return {
    cid: actualCID,
    algorithm: 'sha2-256',
    verified,
  };
}

/**
 * Optional: Pin content to IPFS via pin service (e.g. Infura, Pinata).
 * Requires PIN_SERVICE_URL and PIN_SERVICE_TOKEN in config.
 */
export async function publishToIPFS(
  tarballPath: string,
  config: Partial<{ PIN_SERVICE_URL: string | null; PIN_SERVICE_TOKEN: string | null }> = {}
): Promise<{ cid: string; pinned: boolean; error?: string }> {
  const { cid } = await computePackageCID(tarballPath);
  const pinUrl = config.PIN_SERVICE_URL;
  const token = config.PIN_SERVICE_TOKEN;

  if (!pinUrl || !token) {
    return { cid, pinned: false };
  }

  try {
    const buffer = fs.readFileSync(path.resolve(tarballPath));
    const res = await axios.post(pinUrl, buffer, {
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/octet-stream',
        'Content-Length': buffer.length.toString(),
      },
      maxBodyLength: Infinity,
      maxContentLength: Infinity,
      timeout: 30000,
    });

    if (res.status >= 200 && res.status < 300) {
      return { cid, pinned: true };
    }
    return { cid, pinned: false, error: `Pin service returned ${res.status}` };
  } catch (err) {
    return {
      cid,
      pinned: false,
      error: err instanceof Error ? err.message : 'Unknown error',
    };
  }
}

/**
 * Fetch content from IPFS gateway by CID.
 */
export async function fetchFromIPFS(
  cid: string,
  config: Partial<{ GATEWAY_URL: string }> = {}
): Promise<Buffer | null> {
  const gateway = config.GATEWAY_URL || 'https://ipfs.io';
  const url = `${gateway.replace(/\/$/, '')}/ipfs/${cid}`;

  try {
    const res = await axios.get(url, {
      responseType: 'arraybuffer',
      timeout: 60000,
      validateStatus: (s) => s === 200,
    });
    return Buffer.from(res.data);
  } catch {
    return null;
  }
}
