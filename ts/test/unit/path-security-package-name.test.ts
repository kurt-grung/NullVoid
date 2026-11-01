import { describe, it, expect } from '@jest/globals';
import { validatePackageName } from '../../src/lib/pathSecurity';

describe('validatePackageName', () => {
  it('accepts unscoped npm package names', () => {
    expect(validatePackageName('lodash')).toBe(true);
    expect(validatePackageName('express')).toBe(true);
  });

  it('accepts scoped npm package names', () => {
    expect(validatePackageName('@types/node')).toBe(true);
    expect(validatePackageName('@babel/core')).toBe(true);
  });

  it('rejects traversal and injection patterns', () => {
    expect(validatePackageName('../evil')).toBe(false);
    expect(validatePackageName('pkg;curl')).toBe(false);
  });
});
