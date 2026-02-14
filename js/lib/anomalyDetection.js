/**
 * Extended Anomaly Detection
 *
 * Cross-package anomaly: compare package behavior vs similar packages.
 * Behavioral anomaly: static analysis of package scripts/files.
 */

// Typical npm package stats (from ecosystem research) - used when no sibling packages available.
// Allows cross-package anomaly to contribute when scanning single packages.
const TYPICAL_BASELINE = [
  { scriptCount: 4, scriptTotalLength: 600, dependencyCount: 6, entropyScore: 0.3 },
  { scriptCount: 5, scriptTotalLength: 800, dependencyCount: 8, entropyScore: 0.35 },
  { scriptCount: 3, scriptTotalLength: 400, dependencyCount: 5, entropyScore: 0.25 }
];

function computeCrossPackageAnomaly(pkgFeatures, similarPackages) {
  const baseline = similarPackages && similarPackages.length > 0 ? similarPackages : TYPICAL_BASELINE;

  const n = baseline.length;
  const mean = {
    scriptCount: baseline.reduce((s, p) => s + (p.scriptCount ?? 0), 0) / n,
    scriptTotalLength: baseline.reduce((s, p) => s + (p.scriptTotalLength ?? 0), 0) / n,
    dependencyCount: baseline.reduce((s, p) => s + (p.dependencyCount ?? 0), 0) / n,
    entropyScore: baseline.reduce((s, p) => s + (p.entropyScore ?? 0), 0) / n
  };

  const std = {
    scriptCount: Math.sqrt(baseline.reduce((s, p) => s + Math.pow((p.scriptCount ?? 0) - mean.scriptCount, 2), 0) / n) || 0.001,
    scriptTotalLength: Math.sqrt(baseline.reduce((s, p) => s + Math.pow((p.scriptTotalLength ?? 0) - mean.scriptTotalLength, 2), 0) / n) || 1,
    dependencyCount: Math.sqrt(baseline.reduce((s, p) => s + Math.pow((p.dependencyCount ?? 0) - mean.dependencyCount, 2), 0) / n) || 0.001,
    entropyScore: Math.sqrt(baseline.reduce((s, p) => s + Math.pow((p.entropyScore ?? 0) - mean.entropyScore, 2), 0) / n) || 0.001
  };

  let zSum = 0;
  let count = 0;

  if (pkgFeatures.scriptCount != null) {
    zSum += Math.abs((pkgFeatures.scriptCount - mean.scriptCount) / std.scriptCount);
    count++;
  }
  if (pkgFeatures.scriptTotalLength != null) {
    zSum += Math.min(3, Math.abs((pkgFeatures.scriptTotalLength - mean.scriptTotalLength) / std.scriptTotalLength));
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

function computeBehavioralAnomaly(pkgFeatures) {
  let score = 0;
  if (pkgFeatures.hasPostinstall && (pkgFeatures.postinstallLength ?? 0) > 500) score += 0.3;
  if ((pkgFeatures.scriptCount ?? 0) > 5) score += 0.2;
  if ((pkgFeatures.rareDependencyCount ?? 0) > 2) score += 0.2;
  if ((pkgFeatures.entropyScore ?? 0) > 0.7) score += 0.3;
  return Math.min(1, score);
}

module.exports = {
  computeCrossPackageAnomaly,
  computeBehavioralAnomaly
};
