import { describe, it, expect } from '@jest/globals';
import { isNpmPackageSpec, parsePackageSpec, resolveVersion } from '../../src/lib/remotePackageScan';

describe('remotePackageScan', () => {
  it('detects npm package specs', () => {
    expect(isNpmPackageSpec('lodash')).toBe(true);
    expect(isNpmPackageSpec('lodash@4.17.21')).toBe(true);
    expect(isNpmPackageSpec('@types/node')).toBe(true);
    expect(isNpmPackageSpec('./src')).toBe(false);
    expect(isNpmPackageSpec('/tmp/foo')).toBe(false);
  });

  it('parses name and version', () => {
    expect(parsePackageSpec('express@4.18.2')).toEqual({ name: 'express', version: '4.18.2' });
    expect(parsePackageSpec('chalk')).toEqual({ name: 'chalk', version: 'latest' });
  });

  it('resolves latest from dist-tags', () => {
    const meta = { 'dist-tags': { latest: '2.0.0' }, versions: { '2.0.0': {} } };
    expect(resolveVersion(meta, 'latest')).toBe('2.0.0');
  });
});
