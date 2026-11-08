/**
 * Publish-history features derived from an npm registry document's `time` map.
 *
 * These are the only per-package signals that survive when npm replaces a
 * malicious package with a "security holding package": the placeholder keeps
 * the original version timestamps in `time` but replaces everything else
 * (description, maintainers, repository, README). Training on anything other
 * than `time` and the name would teach the model to recognise the placeholder,
 * not the malware, so both the exporter and the scanner build the ML feature
 * vector from exactly this set.
 */

export interface PublishHistoryFeatures {
  /** Number of published versions (placeholder versions excluded) */
  versionCount: number;
  /** Days between first and last publish (0 for a single version) */
  publishSpanDays: number;
  /** Hours between the first and second publish; 0 when only one version */
  firstToSecondVersionHours: number;
  /** Versions per week over the publish span (versionCount when span < 1 week) */
  versionsPerWeek: number;
  /** Days from first publish to the reference date (advisory date or now) */
  ageAtReferenceDays: number;
  /** Package name length (scope included) */
  nameLength: number;
  /** Shannon entropy of the name in bits per character */
  nameEntropy: number;
  /** Fraction of name characters that are digits */
  nameDigitRatio: number;
  /** Count of '-', '_' and '.' in the name */
  nameSeparatorCount: number;
}

export const PUBLISH_HISTORY_FEATURE_KEYS: ReadonlyArray<keyof PublishHistoryFeatures> = [
  'versionCount',
  'publishSpanDays',
  'firstToSecondVersionHours',
  'versionsPerWeek',
  'ageAtReferenceDays',
  'nameLength',
  'nameEntropy',
  'nameDigitRatio',
  'nameSeparatorCount',
];

/** Versions npm itself publishes when it takes a package down. */
const PLACEHOLDER_VERSION = /-(security|stage|placeholder)$/i;

const DAY_MS = 24 * 60 * 60 * 1000;

export function nameEntropyBits(name: string): number {
  if (!name) return 0;
  const counts = new Map<string, number>();
  for (const ch of name) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / name.length;
    h -= p * Math.log2(p);
  }
  return Math.round(h * 1000) / 1000;
}

/**
 * Return the real publish timestamps from a registry `time` map, oldest first.
 */
export function publishTimestamps(time: Record<string, unknown> | null | undefined): Date[] {
  if (!time || typeof time !== 'object') return [];
  const out: Date[] = [];
  for (const [key, value] of Object.entries(time)) {
    if (key === 'created' || key === 'modified' || key === 'unpublished') continue;
    if (PLACEHOLDER_VERSION.test(key)) continue;
    if (typeof value !== 'string') continue;
    const d = new Date(value);
    if (!Number.isNaN(d.getTime())) out.push(d);
  }
  out.sort((a, b) => a.getTime() - b.getTime());
  return out;
}

/**
 * Features as known at `referenceDate` (default: now). Versions published after
 * the reference date are ignored, so a training row built with the advisory
 * date as reference describes the package as it looked when it was caught, and
 * a benign package can be snapshotted early in its life.
 */
export function publishHistoryFeatures(
  packageName: string,
  time: Record<string, unknown> | null | undefined,
  referenceDate: Date | string | null = null
): PublishHistoryFeatures {
  const ref =
    referenceDate instanceof Date
      ? referenceDate
      : referenceDate
        ? new Date(referenceDate)
        : new Date();
  const all = publishTimestamps(time);
  const stamps = Number.isNaN(ref.getTime())
    ? all
    : all.filter((d) => d.getTime() <= ref.getTime());
  // A reference before the first publish still describes the package by its first version.
  if (stamps.length === 0 && all.length > 0) stamps.push(all[0]!);

  const versionCount = stamps.length;
  const first = stamps[0];
  const last = stamps[stamps.length - 1];
  const publishSpanDays =
    first && last ? Math.max(0, (last.getTime() - first.getTime()) / DAY_MS) : 0;
  const firstToSecondVersionHours =
    stamps.length >= 2
      ? Math.max(0, (stamps[1]!.getTime() - stamps[0]!.getTime()) / (60 * 60 * 1000))
      : 0;
  const spanWeeks = publishSpanDays / 7;
  const versionsPerWeek = spanWeeks >= 1 ? versionCount / spanWeeks : versionCount;
  const ageAtReferenceDays =
    first && !Number.isNaN(ref.getTime())
      ? Math.max(0, (ref.getTime() - first.getTime()) / DAY_MS)
      : 0;

  const bare = packageName.startsWith('@')
    ? packageName.slice(packageName.indexOf('/') + 1)
    : packageName;
  const digits = (bare.match(/[0-9]/g) ?? []).length;

  const round = (n: number, p = 3): number => Math.round(n * 10 ** p) / 10 ** p;
  return {
    versionCount,
    publishSpanDays: round(publishSpanDays),
    firstToSecondVersionHours: round(firstToSecondVersionHours),
    versionsPerWeek: round(versionsPerWeek),
    ageAtReferenceDays: round(ageAtReferenceDays),
    nameLength: packageName.length,
    nameEntropy: nameEntropyBits(bare),
    nameDigitRatio: bare.length > 0 ? round(digits / bare.length) : 0,
    nameSeparatorCount: (bare.match(/[-_.]/g) ?? []).length,
  };
}
