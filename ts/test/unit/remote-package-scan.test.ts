import { describe, it, expect } from '@jest/globals';
import {
  isNpmPackageSpec,
  parsePackageSpec,
  resolveVersion,
  downloadPackageToTemp,
} from '../../src/lib/remotePackageScan';

describe('remotePackageScan', () => {
  it('detects npm package specs', () => {
    expect(isNpmPackageSpec('lodash')).toBe(true);
    expect(isNpmPackageSpec('lodash@4.17.21')).toBe(true);
    expect(isNpmPackageSpec('@types/node')).toBe(true);
    expect(isNpmPackageSpec('@types/node@20.0.0')).toBe(true);
    expect(isNpmPackageSpec('./src')).toBe(false);
    expect(isNpmPackageSpec('/tmp/foo')).toBe(false);
    expect(isNpmPackageSpec('scope/pkg')).toBe(false);
  });

  it('parses name and version', () => {
    expect(parsePackageSpec('express@4.18.2')).toEqual({ name: 'express', version: '4.18.2' });
    expect(parsePackageSpec('chalk')).toEqual({ name: 'chalk', version: 'latest' });
    expect(parsePackageSpec('@scope/pkg@1.0.0')).toEqual({
      name: '@scope/pkg',
      version: '1.0.0',
    });
  });

  it('resolves latest from dist-tags', () => {
    const meta = { 'dist-tags': { latest: '2.0.0' }, versions: { '2.0.0': {} } };
    expect(resolveVersion(meta, 'latest')).toBe('2.0.0');
  });

  it('rejects invalid package names before network fetch', async () => {
    await expect(downloadPackageToTemp('../evil')).resolves.toBeNull();
    await expect(downloadPackageToTemp('pkg;curl')).resolves.toBeNull();
  });

  it('accepts scoped package names for validation', () => {
    expect(parsePackageSpec('@types/node@20.0.0')).toEqual({
      name: '@types/node',
      version: '20.0.0',
    });
  });
});

