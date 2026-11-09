import { describe, it, expect } from '@jest/globals';
import {
  compareVersions,
  normalizeRange,
  versionInRange,
} from '../../src/lib/providers/versionRange';

describe('versionInRange', () => {
  it('handles npm advisory ranges', () => {
    expect(versionInRange('4.17.15', '<4.17.19')).toBe(true);
    expect(versionInRange('4.17.19', '<4.17.19')).toBe(false);
    expect(versionInRange('4.17.21', '<4.17.21')).toBe(false);
    expect(versionInRange('1.5.0', '>=1.0.0 <2.0.0')).toBe(true);
    expect(versionInRange('2.0.0', '>=1.0.0 <2.0.0')).toBe(false);
  });

  it('handles GHSA comma/space ranges', () => {
    expect(normalizeRange('>= 1.0.0, < 1.2.6')).toBe('>=1.0.0 <1.2.6');
    expect(versionInRange('1.2.5', '>= 1.0.0, < 1.2.6')).toBe(true);
    expect(versionInRange('1.2.6', '>= 1.0.0, < 1.2.6')).toBe(false);
    expect(versionInRange('0.2.3', '< 0.2.4')).toBe(true);
    expect(versionInRange('1.2.5', '< 0.2.4')).toBe(false);
  });

  it('treats wildcards and sentinel ranges as npm does', () => {
    expect(versionInRange('1.0.0', '*')).toBe(true);
    expect(versionInRange('1.0.0', '')).toBe(true);
    expect(versionInRange('1.0.0', undefined)).toBe(true);
    expect(versionInRange('1.0.0', '<0.0.0')).toBe(false);
  });

  it('reports rather than hides when a version or range cannot be parsed', () => {
    expect(versionInRange('latest', '<1.0.0')).toBe(true);
    expect(versionInRange('1.0.0', 'not a range')).toBe(true);
    expect(versionInRange('v1.2.3', '<1.2.4')).toBe(true); // coerced
  });

  it('compareVersions orders semver and coerces loose versions', () => {
    expect(compareVersions('1.2.3', '1.10.0')).toBeLessThan(0);
    expect(compareVersions('2.0.0', '1.99.99')).toBeGreaterThan(0);
    expect(compareVersions('1.2', '1.2.0')).toBe(0);
    expect(compareVersions('x', '1.0.0')).toBe(0);
  });
});
