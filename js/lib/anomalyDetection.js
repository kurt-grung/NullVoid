/**
 * Phase 4: Extended Anomaly Detection (JS)
 *
 * Cross-package anomaly: compare package behavior vs similar packages.
 * Behavioral anomaly: static analysis of package scripts/files.
 */

function computeCrossPackageAnomaly(pkgFeatures, similarPackages) {
  if (!similarPackages || similarPackages.length === 0) return 0;

  const n = similarPackages.length;
  const mean = {
    scriptCount: similarPackages.reduce((s, p) => s + (p.scriptCount ?? 0), 0) / n,
    scriptTotalLength: similarPackages.reduce((s, p) => s + (p.scriptTotalLength ?? 0), 0) / n,
    dependencyCount: similarPackages.reduce((s, p) => s + (p.dependencyCount ?? 0), 0) / n,
    entropyScore: similarPackages.reduce((s, p) => s + (p.entropyScore ?? 0), 0) / n
  };

  const std = {
    scriptCount: Math.sqrt(similarPackages.reduce((s, p) => s + Math.pow((p.scriptCount ?? 0) - mean.scriptCount, 2), 0) / n) || 0.001,
    scriptTotalLength: Math.sqrt(similarPackages.reduce((s, p) => s + Math.pow((p.scriptTotalLength ?? 0) - mean.scriptTotalLength, 2), 0) / n) || 1,
    dependencyCount: Math.sqrt(similarPackages.reduce((s, p) => s + Math.pow((p.dependencyCount ?? 0) - mean.dependencyCount, 2), 0) / n) || 0.001,
    entropyScore: Math.sqrt(similarPackages.reduce((s, p) => s + Math.pow((p.entropyScore ?? 0) - mean.entropyScore, 2), 0) / n) || 0.001
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
