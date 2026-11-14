/**
 * Informational ML risk score for a published npm package.
 *
 * The dependency model's score is weak evidence on its own (see
 * AnalyzeDependencyConfusionOptions.emitMlThreats), so this never produces a threat.
 * It only reports what the model says about the package's registry history, for
 * display next to a scan. Returns null when no ML service is configured or reachable;
 * there is no rule-based fallback, so a returned score always came from the model.
 */
import { analyzePackageName, getPackagePublishInfo } from './dependencyConfusion';
import { resolveEmbeddedMlServiceUrl } from './embeddedModel';
import { buildFeatureVector, computeThreatScoreFromModel } from './mlDetection';
import { publishHistoryFeatures } from './publishHistory';

export interface PackageMlRisk {
  /** Model probability (0–1) that the package looks malicious */
  score: number;
  /** Always true: the score is context, not a finding */
  informational: true;
  model: 'dependency';
}

export async function computePackageMlRisk(packageName: string): Promise<PackageMlRisk | null> {
  if (!resolveEmbeddedMlServiceUrl()) return null;
  try {
    const publishInfo = await getPackagePublishInfo(packageName);
    if (!publishInfo) return null;
    const nameAnalysis = analyzePackageName(packageName);
    const features = buildFeatureVector({
      recentCommitCount: 0,
      scopeType: nameAnalysis.scopeType ?? null,
      suspiciousPatternsCount: nameAnalysis.suspiciousPatterns?.length ?? 0,
      registryName: 'npm',
      creationDate: publishInfo.created,
      firstCommitDate: null,
      publishHistory: publishHistoryFeatures(packageName, publishInfo.time),
    });
    const { score } = await computeThreatScoreFromModel(features);
    if (score == null || !Number.isFinite(score)) return null;
    return { score, informational: true, model: 'dependency' };
  } catch {
    return null;
  }
}
