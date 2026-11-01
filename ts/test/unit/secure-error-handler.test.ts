import * as path from 'path';
import * as os from 'os';
import { describe, it, expect } from '@jest/globals';
import { InputValidator, PathTraversalError, ValidationError } from '../../src/lib/secureErrorHandler';

describe('InputValidator.validateFilePath', () => {
  const base = os.tmpdir();

  it('accepts a valid path inside the base directory', () => {
    const result = InputValidator.validateFilePath('subdir/file.txt', base);
    expect(result).toBe(path.resolve(base, 'subdir/file.txt'));
  });

  it('rejects a plain path traversal sequence', () => {
    expect(() => InputValidator.validateFilePath('../outside.txt', base)).toThrow(PathTraversalError);
  });

  it('rejects a path that resolves to a sibling directory (startsWith false-positive guard)', () => {
    // e.g. base = /tmp, attempt to reach /tmp-evil via relative path
    const siblingDir = path.basename(base) + '-evil';
    expect(() =>
      InputValidator.validateFilePath(`../${siblingDir}/file`, base)
    ).toThrow(PathTraversalError);
  });

  it('accepts a path that is exactly the base directory', () => {
    const result = InputValidator.validateFilePath('.', base);
    expect(result).toBe(path.resolve(base));
  });

  it('rejects an empty string', () => {
    expect(() => InputValidator.validateFilePath('', base)).toThrow(ValidationError);
  });
});

describe('InputValidator.validatePackageName', () => {
  it('accepts a plain package name', () => {
    expect(InputValidator.validatePackageName('lodash')).toBe('lodash');
  });

  it('accepts a dotted package name like @types-style plain names', () => {
    expect(InputValidator.validatePackageName('react')).toBe('react');
  });

  it('rejects an empty name', () => {
    expect(() => InputValidator.validatePackageName('')).toThrow(ValidationError);
  });

  it('rejects a name with shell-injection characters', () => {
    expect(() => InputValidator.validatePackageName('evil;rm -rf')).toThrow();
  });
});
