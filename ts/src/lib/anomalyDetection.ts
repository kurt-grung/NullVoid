/**
 * Phase 4: Extended Anomaly Detection
 *
 * Cross-package anomaly: compare package behavior vs similar packages.
 * Behavioral anomaly: static analysis of package scripts/files.
 */

/** Typical npm package stats - used when no sibling packages available */
const TYPICAL_BASELINE: SimilarPackageStats[] = [
  { scriptCount: 4, scriptTotalLength: 600, dependencyCount: 6, entropyScore: 0.3 },
  { scriptCount: 5, scriptTotalLength: 800, dependencyCount: 8, entropyScore: 0.35 },
  { scriptCount: 3, scriptTotalLength: 400, dependencyCount: 5, entropyScore: 0.25 },
];

export interface PackageFeatures {
  /** Number of lifecycle scripts (postinstall, preinstall, etc.) */
  scriptCount?: number;
  /** Total length of script bodies (chars) */
  scriptTotalLength?: number;
  /** Has postinstall script */
  hasPostinstall?: boolean;
  /** Postinstall script length */
  postinstallLength?: number;
  /** Number of dependencies */
  dependencyCount?: number;
  /** Number of devDependencies */
  devDependencyCount?: number;
  /** Entropy score from code analysis (0-1) */
  entropyScore?: number;
  /** Rare dependency combination indicator */
  rareDependencyCount?: number;
}

export interface SimilarPackageStats {
  scriptCount: number;
  scriptTotalLength: number;
  dependencyCount: number;
  entropyScore: number;
}

/**
 * Compute cross-package anomaly: deviation of this package's features from cluster mean.
 * Returns 0-1 score; higher = more anomalous.
 */
export function computeCrossPackageAnomaly(
  pkgFeatures: PackageFeatures,
  similarPackages: SimilarPackageStats[]
): number {
  const baseline =
    similarPackages && similarPackages.length > 0 ? similarPackages : TYPICAL_BASELINE;

  const n = baseline.length;
  const mean = {
    scriptCount: baseline.reduce((s, p) => s + (p.scriptCount ?? 0), 0) / n,
    scriptTotalLength: baseline.reduce((s, p) => s + (p.scriptTotalLength ?? 0), 0) / n,
    dependencyCount: baseline.reduce((s, p) => s + (p.dependencyCount ?? 0), 0) / n,
    entropyScore: baseline.reduce((s, p) => s + (p.entropyScore ?? 0), 0) / n,
  };

  const std = {
    scriptCount:
      Math.sqrt(
        baseline.reduce((s, p) => s + Math.pow((p.scriptCount ?? 0) - mean.scriptCount, 2), 0) / n
      ) || 0.001,
    scriptTotalLength:
      Math.sqrt(
        baseline.reduce(
          (s, p) => s + Math.pow((p.scriptTotalLength ?? 0) - mean.scriptTotalLength, 2),
          0
        ) / n
      ) || 1,
    dependencyCount:
      Math.sqrt(
        baseline.reduce(
          (s, p) => s + Math.pow((p.dependencyCount ?? 0) - mean.dependencyCount, 2),
          0
        ) / n
      ) || 0.001,
    entropyScore:
      Math.sqrt(
        baseline.reduce((s, p) => s + Math.pow((p.entropyScore ?? 0) - mean.entropyScore, 2), 0) / n
      ) || 0.001,
  };

  let zSum = 0;
  let count = 0;

  if (pkgFeatures.scriptCount != null) {
    zSum += Math.abs((pkgFeatures.scriptCount - mean.scriptCount) / std.scriptCount);
    count++;
  }
  if (pkgFeatures.scriptTotalLength != null) {
    zSum += Math.min(
      3,
      Math.abs((pkgFeatures.scriptTotalLength - mean.scriptTotalLength) / std.scriptTotalLength)
    );
    count++;
  }
  if (pkgFeatures.dependencyCount != null) {
    zSum += Math.abs((pkgFeatures.dependencyCount - mean.dependencyCount) / std.dependencyCount);
    count++;
  }
  if (pkgFeatures.entropyScore != null) {
    zSum += Math.abs((pkgFeatures.entropyScore - mean.entropyScore) / std.entropyScore);
    count++;
  }

  if (count === 0) return 0;
  const avgZ = zSum / count;
  return Math.min(1, avgZ / 3);
}

/**
 * Compute behavioral anomaly from package features.
 * Unusual postinstall complexity, rare dependency combinations, high entropy.
 */
export function computeBehavioralAnomaly(pkgFeatures: PackageFeatures): number {
  let score = 0;

  if (pkgFeatures.hasPostinstall && (pkgFeatures.postinstallLength ?? 0) > 500) {
    score += 0.3;
  }
  if ((pkgFeatures.scriptCount ?? 0) > 5) {
    score += 0.2;
  }
  if ((pkgFeatures.rareDependencyCount ?? 0) > 2) {
    score += 0.2;
  }
  if ((pkgFeatures.entropyScore ?? 0) > 0.7) {
    score += 0.3;
  }

  return Math.min(1, score);
}
