import { describe, it, expect } from '@jest/globals';
import { assertSafeTarballEntry, PathTraversalError } from '../../src/lib/pathSecurity';
import * as os from 'os';
import * as path from 'path';

describe('assertSafeTarballEntry', () => {
  const extractRoot = path.join(os.tmpdir(), 'nullvoid-tarball-test');

  it('allows paths inside the extraction root', () => {
    expect(() => assertSafeTarballEntry('package/index.js', extractRoot)).not.toThrow();
    expect(() => assertSafeTarballEntry('lib/utils.js', extractRoot)).not.toThrow();
  });

  it('rejects parent directory traversal', () => {
    expect(() => assertSafeTarballEntry('../outside.js', extractRoot)).toThrow(PathTraversalError);
  });

  it('rejects absolute paths', () => {
    expect(() => assertSafeTarballEntry('/etc/passwd', extractRoot)).toThrow(PathTraversalError);
  });

  it('rejects null bytes', () => {
    expect(() => assertSafeTarballEntry('pkg/\0.js', extractRoot)).toThrow(PathTraversalError);
  });
});
