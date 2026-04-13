import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import {
  setTrustStorePath,
  getTrustScore,
  recordVerification,
  recordScanResult,
} from '../../src/lib/trustNetwork';

describe('trustNetwork', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nullvoid-trust-'));
    setTrustStorePath(path.join(tempDir, 'trust.json'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('returns null for an unknown package', async () => {
    const score = await getTrustScore('unknown-pkg', '1.0.0');
    expect(score).toBeNull();
  });

  it('records a verification and retrieves a trust score of 1', async () => {
    await recordVerification('lodash', '4.17.21', 'bafk-test-cid', 'publisher-a');
    const score = await getTrustScore('lodash', '4.17.21');
    expect(score).toBe(1);
  });

  it('records a failed scan and returns a lower trust score', async () => {
    await recordScanResult('evil-pkg', '0.0.1', false);
    const score = await getTrustScore('evil-pkg', '0.0.1');
    expect(score).not.toBeNull();
    expect(score as number).toBeLessThan(1);
  });

  it('persists data across instances (reads from disk)', async () => {
    await recordVerification('persistent-pkg', '1.0.0', 'bafk-persist');
    // Re-point to same store (simulate new process)
    setTrustStorePath(path.join(tempDir, 'trust.json'));
    const score = await getTrustScore('persistent-pkg', '1.0.0');
    expect(score).toBe(1);
  });

  it('does not throw when the trust store file is corrupt', async () => {
    const storePath = path.join(tempDir, 'trust.json');
    fs.writeFileSync(storePath, '{{{invalid json', 'utf8');
    setTrustStorePath(storePath);
    await expect(getTrustScore('any', '1.0.0')).resolves.toBeNull();
  });
});
