/**
 * ML Detection scaffold (Phase 2)
 *
 * Lightweight threat scoring from timeline + pattern features. Uses
 * statistical anomaly and rule-based scores; structured for future
 * ML model integration (e.g. loaded model or API).
 */

const { DEPENDENCY_CONFUSION_CONFIG } = require('./config');
const { timelineAnomalyScore, analyzeTimeline } = require('./timelineAnalysis');

const PHASE2 = DEPENDENCY_CONFUSION_CONFIG?.PHASE2_DETECTION ?? {};
const ML_ENABLED = PHASE2.ML_SCORING !== false;
const ANOMALY_THRESHOLD = PHASE2.ML_ANOMALY_THRESHOLD ?? 0.7;

/**
 * Build a feature vector for a package (for future ML model)
 * @param {Object} params - timeline + name + scope + git activity
 * @returns {Object} Feature set
 */
function buildFeatureVector(params) {
  const {
    daysDifference = null,
    recentCommitCount = 0,
    scopeType = null,
    suspiciousPatternsCount = 0,
    registryName = null
  } = params;
  const timeline = analyzeTimeline({
    registryCreated: params.registryCreated ?? params.creationDate,
    firstCommitDate: params.firstCommitDate,
    recentCommitCount,
    scopeType
  });
  return {
    daysDifference: daysDifference ?? timeline.daysDifference ?? 365,
    recentCommitCount,
    scopePrivate: scopeType === 'PRIVATE' ? 1 : 0,
    suspiciousPatternsCount,
    timelineAnomaly: timeline.anomalyScore,
    registryIsNpm: registryName === 'npm' ? 1 : 0
  };
}

/**
 * Compute a single threat score (0–1) from features. Currently rule-based;
 * can be replaced by ML model inference later.
 * @param {Object} features - From buildFeatureVector
 * @returns {number} Score 0–1
 */
function computeThreatScore(features) {
  let score = 0;
  if (features.timelineAnomaly != null) score += 0.5 * features.timelineAnomaly;
  if (features.scopePrivate === 1) score += 0.2;
  if (features.suspiciousPatternsCount > 0) score += Math.min(0.2, 0.1 * features.suspiciousPatternsCount);
  if (features.recentCommitCount < 5 && features.daysDifference < 30) score += 0.1;
  return Math.min(1, score);
}

/**
 * Run Phase 2 ML-style detection: anomaly score + threat score
 * @param {Object} params - Same as dependency confusion analysis (package name, path, registry + git data)
 * @returns {Object} { enabled, anomalyScore, threatScore, aboveThreshold, features }
 */
function runMLDetection(params) {
  const enabled = ML_ENABLED;
  const timeline = analyzeTimeline({
    registryCreated: params.creationDate ?? params.registryCreated,
    firstCommitDate: params.firstCommitDate,
    recentCommitCount: params.recentCommitCount ?? 0,
    scopeType: params.scopeType
  });
  const features = buildFeatureVector({
    daysDifference: timeline.daysDifference,
    recentCommitCount: params.recentCommitCount ?? 0,
    scopeType: params.scopeType,
    suspiciousPatternsCount: params.suspiciousPatternsCount ?? 0,
    registryName: params.registryName,
    creationDate: params.creationDate,
    firstCommitDate: params.firstCommitDate
  });
  const threatScore = computeThreatScore(features);
  const anomalyScore = timeline.anomalyScore;
  const aboveThreshold = enabled && (threatScore >= ANOMALY_THRESHOLD || anomalyScore >= ANOMALY_THRESHOLD);
  return {
    enabled,
    anomalyScore,
    threatScore,
    aboveThreshold,
    features
  };
}

module.exports = {
  buildFeatureVector,
  computeThreatScore,
  runMLDetection
};
