import { describe, it, expect } from '@jest/globals';
import {
  nameEntropyBits,
  publishHistoryFeatures,
  publishTimestamps,
  PUBLISH_HISTORY_FEATURE_KEYS,
} from '../../src/lib/publishHistory';
import manifest from '../../../ml-model/feature-keys.json';

const DAY = 24 * 60 * 60 * 1000;

describe('publishHistory', () => {
  it('ignores created/modified and npm placeholder versions', () => {
    const stamps = publishTimestamps({
      created: '2026-11-06T17:46:30.367Z', // holding package date
      modified: '2026-11-06T17:48:06.992Z',
      '1.0.0': '2026-04-07T03:08:46.898Z',
      '0.0.0-stage': '2026-11-06T17:46:30.367Z',
      '0.0.1-security': '2026-11-06T17:48:06.716Z',
    });
    expect(stamps.map((d) => d.toISOString())).toEqual(['2026-04-07T03:08:46.898Z']);
  });

  it('describes a single-version package', () => {
    const f = publishHistoryFeatures(
      'monobomber',
      { '1.0.0': '2026-04-07T03:08:46.898Z' },
      '2026-04-10T03:08:46.898Z'
    );
    expect(f.versionCount).toBe(1);
    expect(f.publishSpanDays).toBe(0);
    expect(f.firstToSecondVersionHours).toBe(0);
    expect(f.versionsPerWeek).toBe(1);
    expect(f.ageAtReferenceDays).toBe(3);
    expect(f.nameLength).toBe(10);
    expect(f.nameDigitRatio).toBe(0);
    expect(f.nameSeparatorCount).toBe(0);
  });

  it('computes span, cadence and name shape for a long-lived package', () => {
    const first = Date.parse('2020-01-01T00:00:00Z');
    const time: Record<string, string> = {};
    for (let i = 0; i < 20; i++) time[`1.${i}.0`] = new Date(first + i * 7 * DAY).toISOString();
    const f = publishHistoryFeatures('@scope/my-lib_2', time, new Date(first + 365 * DAY));
    expect(f.versionCount).toBe(20);
    expect(f.publishSpanDays).toBe(133);
    expect(f.firstToSecondVersionHours).toBe(168);
    expect(f.versionsPerWeek).toBeCloseTo(20 / 19, 3);
    expect(f.ageAtReferenceDays).toBe(365);
    expect(f.nameLength).toBe('@scope/my-lib_2'.length);
    expect(f.nameSeparatorCount).toBe(2); // '-' and '_' in the bare name
    expect(f.nameDigitRatio).toBeCloseTo(1 / 'my-lib_2'.length, 3);
  });

  it('truncates history at the reference date (what was known then)', () => {
    const time = {
      '1.0.0': '2024-01-01T00:00:00Z',
      '1.1.0': '2024-01-03T00:00:00Z',
      '2.0.0': '2025-01-01T00:00:00Z',
    };
    const early = publishHistoryFeatures('pkg', time, '2024-01-10T00:00:00Z');
    const late = publishHistoryFeatures('pkg', time, '2025-06-01T00:00:00Z');
    expect(early.versionCount).toBe(2);
    expect(late.versionCount).toBe(3);
    // A reference before the first publish still describes the first version.
    expect(publishHistoryFeatures('pkg', time, '2020-01-01T00:00:00Z').versionCount).toBe(1);
  });

  it('name entropy is 0 for a repeated character and higher for mixed names', () => {
    expect(nameEntropyBits('aaaa')).toBe(0);
    expect(nameEntropyBits('abcd')).toBe(2);
    expect(nameEntropyBits('x7q9zk2p')).toBeGreaterThan(nameEntropyBits('lodash'));
  });

  it('is empty-safe', () => {
    const f = publishHistoryFeatures('x', null);
    expect(f.versionCount).toBe(0);
    expect(f.ageAtReferenceDays).toBe(0);
  });

  it('matches the dependency feature manifest (schema v2)', () => {
    expect(manifest.version).toBe(2);
    for (const key of PUBLISH_HISTORY_FEATURE_KEYS) {
      expect(manifest.dependency).toContain(key);
    }
  });
});
