/**
 * ML Detection scaffold
 *
 * Lightweight threat scoring from timeline + pattern + commit-pattern features.
 * Supports rule-based weights, commit pattern analysis, and pluggable ML model
 * (external API or local Node module).
 */

import * as path from 'path';
import * as http from 'http';
import * as https from 'https';
import { DEPENDENCY_CONFUSION_CONFIG } from './config';
import { analyzeTimeline } from './timelineAnalysis';
import {
  analyzeCommitPatterns,
  commitPatternAnomalyScore,
  type CommitPatterns,
} from './commitPatternAnalysis';
import type { NlpAnalysisResult } from './nlpAnalysis';
import type { CommunityAnalysisResult } from './communityAnalysis';

const DEFAULT_ML_WEIGHTS: Record<string, number> = {
  timelineAnomaly: 0.4,
  scopePrivate: 0.15,
  suspiciousPatterns: 0.15,
  lowActivityRecent: 0.08,
  commitPatternAnomaly: 0.08,
  nlpSecurityScore: 0.08,
  crossPackageAnomaly: 0.03,
  behavioralAnomaly: 0.03,
  reviewSecurityScore: 0.05,
  popularityScore: 0.02,
  trustScore: 0.05,
};

const ML_CFG =
  (DEPENDENCY_CONFUSION_CONFIG as { ML_DETECTION?: MLDetectionConfig }).ML_DETECTION ?? {};
const ML_ENABLED = ML_CFG.ML_SCORING !== false;
const ANOMALY_THRESHOLD = ML_CFG.ML_ANOMALY_THRESHOLD ?? 0.7;
const ML_WEIGHTS = ML_CFG.ML_WEIGHTS ?? DEFAULT_ML_WEIGHTS;
const ML_MODEL_URL = ML_CFG.ML_MODEL_URL || null;
const ML_MODEL_PATH = ML_CFG.ML_MODEL_PATH || null;
const ML_EXPLAIN = ML_CFG.ML_EXPLAIN === true;
const COMMIT_PATTERN_ENABLED = ML_CFG.COMMIT_PATTERN_ANALYSIS !== false;
const MODEL_TIMEOUT = 5000;

export interface MLDetectionConfig {
  ML_SCORING?: boolean;
  ML_ANOMALY_THRESHOLD?: number;
  ML_WEIGHTS?: Record<string, number>;
  ML_MODEL_URL?: string | null;
  ML_MODEL_PATH?: string | null;
  ML_EXPLAIN?: boolean;
  COMMIT_PATTERN_ANALYSIS?: boolean;
}

export interface FeatureVector {
  daysDifference: number;
  recentCommitCount: number;
  scopePrivate: number;
  suspiciousPatternsCount: number;
  timelineAnomaly: number;
  registryIsNpm: number;
  authorCount?: number;
  totalCommitCount?: number;
  dominantAuthorShare?: number;
  commitPatternAnomaly?: number;
  branchCount?: number;
  recentCommitCount90d?: number;
  messageAnomalyScore?: number;
  diffAnomalyScore?: number;
  nlpSecurityScore?: number;
  nlpSuspiciousCount?: number;
  crossPackageAnomaly?: number;
  behavioralAnomaly?: number;
  reviewSecurityScore?: number;
  popularityScore?: number;
  trustScore?: number;
}

export interface MLDetectionParams {
  creationDate?: Date | string | null;
  registryCreated?: Date | string | null;
  firstCommitDate?: Date | string | null;
  recentCommitCount?: number;
  scopeType?: 'PRIVATE' | 'PUBLIC' | 'UNKNOWN' | null;
  suspiciousPatternsCount?: number;
  registryName?: string | null;
  packagePath?: string;
  commitPatterns?: CommitPatterns | null;
  nlpResult?: NlpAnalysisResult | null;
  crossPackageAnomaly?: number | null;
  behavioralAnomaly?: number | null;
  communityResult?: CommunityAnalysisResult | null;
  trustScore?: number | null;
}

export interface MLDetectionResult {
  enabled: boolean;
  anomalyScore: number;
  threatScore: number;
  aboveThreshold: boolean;
  predictiveScore: number;
  predictiveRisk: boolean;
  features: FeatureVector;
  modelUsed: boolean;
  /** Human-readable reasons when explain requested and model supports it */
  reasons?: string[];
  /** Feature importance when explain requested */
  importance?: Record<string, number>;
}

/**
 * Build a feature vector for a package (for rule-based or ML model)
 */
export function buildFeatureVector(
  params: MLDetectionParams & {
    daysDifference?: number | null | undefined;
    registryCreated?: Date | string | null | undefined;
    creationDate?: Date | string | null | undefined;
  }
): FeatureVector {
  const {
    daysDifference = null,
    recentCommitCount = 0,
    scopeType = null,
    suspiciousPatternsCount = 0,
    registryName = null,
    commitPatterns = null,
    nlpResult = null,
    crossPackageAnomaly = null,
    behavioralAnomaly = null,
    communityResult = null,
    trustScore = null,
  } = params;
  const timeline = analyzeTimeline({
    registryCreated: params.registryCreated ?? params.creationDate ?? null,
    firstCommitDate: params.firstCommitDate ?? null,
    recentCommitCount,
    scopeType: scopeType ?? null,
  });
  const features: FeatureVector = {
    daysDifference: daysDifference ?? timeline.daysDifference ?? 365,
    recentCommitCount,
    scopePrivate: scopeType === 'PRIVATE' ? 1 : 0,
    suspiciousPatternsCount,
    timelineAnomaly: timeline.anomalyScore,
    registryIsNpm: registryName === 'npm' ? 1 : 0,
  };
  if (commitPatterns) {
    features.authorCount = commitPatterns.authorCount ?? 0;
    features.totalCommitCount = commitPatterns.totalCommitCount ?? 0;
    features.dominantAuthorShare = commitPatterns.dominantAuthorShare ?? 0;
    features.commitPatternAnomaly = commitPatternAnomalyScore(commitPatterns);
    features.branchCount = commitPatterns.branchCount ?? 0;
    features.recentCommitCount90d = commitPatterns.recentCommitCount90d ?? 0;
    if (commitPatterns.messageAnomalyScore != null)
      features.messageAnomalyScore = commitPatterns.messageAnomalyScore;
    if (commitPatterns.diffAnomalyScore != null)
      features.diffAnomalyScore = commitPatterns.diffAnomalyScore;
  }
  if (nlpResult) {
    features.nlpSecurityScore = nlpResult.nlpSecurityScore ?? nlpResult.securityScore ?? 0;
    features.nlpSuspiciousCount =
      nlpResult.nlpSuspiciousCount ?? nlpResult.suspiciousPhrases?.length ?? 0;
  }
  if (crossPackageAnomaly != null) features.crossPackageAnomaly = crossPackageAnomaly;
  if (behavioralAnomaly != null) features.behavioralAnomaly = behavioralAnomaly;
  if (communityResult) {
    features.reviewSecurityScore = 1 - (communityResult.reviewSecurityScore ?? 0.5);
    features.popularityScore = 1 - (communityResult.popularityScore ?? 0.5);
  }
  if (trustScore != null) features.trustScore = 1 - trustScore;
  return features;
}

/**
 * Compute a single threat score (0–1) from features using configurable ML weights
 */
export function computeThreatScore(
  features: FeatureVector,
  weights: Record<string, number> = ML_WEIGHTS
): number {
  let score = 0;
  if (features.timelineAnomaly != null && weights['timelineAnomaly'])
    score += weights['timelineAnomaly'] * features.timelineAnomaly;
  if (features.scopePrivate === 1 && weights['scopePrivate']) score += weights['scopePrivate'];
  if (features.suspiciousPatternsCount > 0 && weights['suspiciousPatterns'])
    score += Math.min(
      weights['suspiciousPatterns'],
      0.1 * features.suspiciousPatternsCount * (weights['suspiciousPatterns'] / 0.2)
    );
  if (
    weights['lowActivityRecent'] &&
    features.recentCommitCount < 5 &&
    features.daysDifference < 30
  )
    score += weights['lowActivityRecent'];
  if (features.commitPatternAnomaly != null && weights['commitPatternAnomaly'])
    score += weights['commitPatternAnomaly'] * features.commitPatternAnomaly;
  if (features.nlpSecurityScore != null && weights['nlpSecurityScore'])
    score += weights['nlpSecurityScore'] * features.nlpSecurityScore;
  if (features.crossPackageAnomaly != null && weights['crossPackageAnomaly'])
    score += weights['crossPackageAnomaly'] * features.crossPackageAnomaly;
  if (features.behavioralAnomaly != null && weights['behavioralAnomaly'])
    score += weights['behavioralAnomaly'] * features.behavioralAnomaly;
  if (features.reviewSecurityScore != null && weights['reviewSecurityScore'])
    score += weights['reviewSecurityScore'] * features.reviewSecurityScore;
  if (features.popularityScore != null && weights['popularityScore'])
    score += weights['popularityScore'] * features.popularityScore;
  if (features.trustScore != null && weights['trustScore'])
    score += weights['trustScore'] * features.trustScore;
  return Math.min(1, score);
}

/**
 * Call external ML model API (POST features, expect { score: 0-1 })
 * When explain is true, sends { features, explain: true } and may receive { score, reasons?, importance? }
 */
function fetchModelScoreFromUrl(
  url: string,
  features: FeatureVector,
  timeout: number = MODEL_TIMEOUT,
  explain: boolean = false
): Promise<{ score: number | null; reasons?: string[]; importance?: Record<string, number> }> {
  return new Promise((resolve) => {
    const payload = JSON.stringify({ features, explain });
    const u = new URL(url);
    const options = {
      hostname: u.hostname,
      port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
        'User-Agent': 'NullVoid-Security-Scanner/2.0',
      },
      timeout,
    };
    const protocol = u.protocol === 'https:' ? https : http;
    const req = protocol.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      res.on('end', () => {
        try {
          const json = data ? JSON.parse(data) : null;
          const score = json != null && typeof json.score === 'number' ? json.score : null;
          const clamped = score != null ? Math.max(0, Math.min(1, score)) : null;
          resolve({
            score: clamped,
            reasons: Array.isArray(json?.reasons) ? json.reasons : undefined,
            importance:
              json?.importance && typeof json.importance === 'object' ? json.importance : undefined,
          });
        } catch {
          resolve({ score: null });
        }
      });
    });
    req.on('error', () => resolve({ score: null }));
    req.setTimeout(timeout, () => {
      req.destroy();
      resolve({ score: null });
    });
    req.write(payload);
    req.end();
  });
}

/**
 * Call local ML model module (exports score(features) => number)
 */
async function getModelScoreFromPath(
  modulePath: string,
  features: FeatureVector
): Promise<number | null> {
  try {
    const { createRequire } = await import('module');
    const requireMod = createRequire(require.resolve('./config'));
    const absPath = path.isAbsolute(modulePath)
      ? modulePath
      : path.resolve(process.cwd(), modulePath);
    const mod = requireMod(absPath) as {
      score?: (f: FeatureVector) => number;
      predict?: (f: FeatureVector) => number;
      default?: (f: FeatureVector) => number;
    };
    const fn = mod.score ?? mod.predict ?? mod.default;
    if (typeof fn !== 'function') return null;
    const score = fn(features);
    if (typeof score !== 'number') return null;
    return Math.max(0, Math.min(1, score));
  } catch {
    return null;
  }
}

/**
 * Get threat score from configured ML model (API or local module), or null to use rule-based
 */
async function computeThreatScoreFromModel(
  features: FeatureVector
): Promise<{ score: number | null; reasons?: string[]; importance?: Record<string, number> }> {
  if (ML_MODEL_URL) {
    const result = await fetchModelScoreFromUrl(ML_MODEL_URL, features, MODEL_TIMEOUT, ML_EXPLAIN);
    if (result.score != null) return result;
  }
  if (ML_MODEL_PATH) {
    const score = await getModelScoreFromPath(ML_MODEL_PATH, features);
    if (score != null) return { score };
  }
  return { score: null };
}

/**
 * Compute a predictive risk score (0–1) from features
 */
export function computePredictiveScore(features: FeatureVector): number {
  let s = 0;
  if (features.timelineAnomaly != null) s += 0.4 * features.timelineAnomaly;
  if (features.commitPatternAnomaly != null) s += 0.25 * features.commitPatternAnomaly;
  if (features.recentCommitCount < 5 && (features.daysDifference ?? 365) < 90) s += 0.15;
  if (features.nlpSecurityScore != null) s += 0.15 * features.nlpSecurityScore;
  if (features.crossPackageAnomaly != null) s += 0.05 * features.crossPackageAnomaly;
  if (features.reviewSecurityScore != null) s += 0.05 * features.reviewSecurityScore;
  if (features.popularityScore != null) s += 0.05 * features.popularityScore;
  return Math.min(1, s);
}

/**
 * Run ML-style detection: anomaly score + threat score (rule-based or model)
 */
export async function runMLDetection(params: MLDetectionParams): Promise<MLDetectionResult> {
  const enabled = ML_ENABLED;
  let commitPatterns = params.commitPatterns ?? null;
  if (COMMIT_PATTERN_ENABLED && params.packagePath && !commitPatterns)
    commitPatterns = analyzeCommitPatterns(params.packagePath);

  const timeline = analyzeTimeline({
    registryCreated: params.creationDate ?? params.registryCreated ?? null,
    firstCommitDate: params.firstCommitDate ?? null,
    recentCommitCount: params.recentCommitCount ?? 0,
    scopeType: params.scopeType ?? null,
  });
  const buildParams: Parameters<typeof buildFeatureVector>[0] = {
    daysDifference: timeline.daysDifference ?? undefined,
    recentCommitCount: params.recentCommitCount ?? 0,
    scopeType: params.scopeType ?? null,
    suspiciousPatternsCount: params.suspiciousPatternsCount ?? 0,
    registryName: params.registryName ?? null,
    creationDate: params.creationDate ?? null,
    firstCommitDate: params.firstCommitDate ?? null,
    commitPatterns: commitPatterns ?? null,
    nlpResult: params.nlpResult ?? null,
    crossPackageAnomaly: params.crossPackageAnomaly ?? null,
    behavioralAnomaly: params.behavioralAnomaly ?? null,
    communityResult: params.communityResult ?? null,
    trustScore: params.trustScore ?? null,
  };
  const features = buildFeatureVector(buildParams);

  let threatScore: number | null = null;
  let modelUsed = false;
  let reasons: string[] | undefined;
  let importance: Record<string, number> | undefined;
  if (ML_MODEL_URL || ML_MODEL_PATH) {
    const result = await computeThreatScoreFromModel(features);
    threatScore = result.score;
    if (threatScore != null) modelUsed = true;
    reasons = result.reasons;
    importance = result.importance;
  }
  if (threatScore == null) threatScore = computeThreatScore(features);

  const anomalyScore = timeline.anomalyScore;
  const aboveThreshold =
    enabled && (threatScore >= ANOMALY_THRESHOLD || anomalyScore >= ANOMALY_THRESHOLD);
  const predictiveScore = computePredictiveScore(features);
  const predictiveRisk = enabled && !aboveThreshold && predictiveScore >= 0.4;
  return {
    enabled,
    anomalyScore,
    threatScore,
    aboveThreshold,
    predictiveScore,
    predictiveRisk,
    features,
    modelUsed,
    ...(reasons && { reasons }),
    ...(importance && { importance }),
  };
}

export { computeThreatScoreFromModel };
