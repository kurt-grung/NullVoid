/**
 * One semver range check for every IoC provider.
 *
 * Each provider used to carry its own hand-rolled comparator; they disagreed
 * (`<4.17.21` was never handled by one, `>= 1.0.0, < 1.2.6` split on the
 * wrong boundary in another) and every gap became a false positive, because
 * an unparsable range was treated as "vulnerable".
 */

import semver from 'semver';

/**
 * Normalise the range syntaxes providers emit into something semver parses:
 *   GHSA   ">= 1.0.0, < 1.2.6"      → ">=1.0.0 <1.2.6"
 *   npm    "<4.17.19"               → unchanged
 *   Snyk   "[1.0.0,2.0.0)" is not used by the npm feed; ">=1 <2" passes through
 */
export function normalizeRange(range: string): string {
  return range
    .trim()
    .replace(/,/g, ' ')
    .replace(/([<>]=?|=)\s+/g, '$1')
    .replace(/\s+/g, ' ');
}

/**
 * True when `version` is inside `range`. A range that cannot be parsed is
 * treated as matching (the advisory is reported) so a syntax we have not seen
 * fails loud rather than silently hiding a vulnerability; a version that
 * cannot be parsed at all also matches, for the same reason.
 */
export function versionInRange(version: string, range: string | undefined | null): boolean {
  if (!range || range.trim() === '' || range.trim() === '*') return true;
  if (range.trim() === '<0.0.0') return false;
  const v = semver.valid(version) ?? semver.valid(semver.coerce(version));
  if (!v) return true;
  const r = semver.validRange(normalizeRange(range), { includePrerelease: true });
  if (!r) return true;
  return semver.satisfies(v, r, { includePrerelease: true });
}

/** semver.compare with coercion; unparsable versions compare equal (0). */
export function compareVersions(a: string, b: string): number {
  const va = semver.valid(a) ?? semver.valid(semver.coerce(a));
  const vb = semver.valid(b) ?? semver.valid(semver.coerce(b));
  if (!va || !vb) return 0;
  return semver.compare(va, vb);
}
