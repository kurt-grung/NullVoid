/**
 * ML Detection scaffold (Phase 2)
 *
 * Lightweight threat scoring from timeline + pattern + commit-pattern features.
 * Supports rule-based weights, commit pattern analysis, and pluggable ML model
 * (external API or local Node module).
 */

const path = require('path');
const http = require('http');
const https = require('https');
const { DEPENDENCY_CONFUSION_CONFIG } = require('./config');
const { analyzeTimeline } = require('./timelineAnalysis');
const { analyzeCommitPatterns, commitPatternAnomalyScore } = require('./commitPatternAnalysis');

const PHASE2 = DEPENDENCY_CONFUSION_CONFIG?.PHASE2_DETECTION ?? {};
const ML_ENABLED = PHASE2.ML_SCORING !== false;
const ANOMALY_THRESHOLD = PHASE2.ML_ANOMALY_THRESHOLD ?? 0.7;
const ML_WEIGHTS = PHASE2.ML_WEIGHTS ?? {
  timelineAnomaly: 0.4,
  scopePrivate: 0.15,
  suspiciousPatterns: 0.15,
  lowActivityRecent: 0.08,
  commitPatternAnomaly: 0.08,
  nlpSecurityScore: 0.08,
  crossPackageAnomaly: 0.03,
  behavioralAnomaly: 0.03
};
const ML_MODEL_URL = PHASE2.ML_MODEL_URL || null;
const ML_MODEL_PATH = PHASE2.ML_MODEL_PATH || null;
const COMMIT_PATTERN_ENABLED = PHASE2.COMMIT_PATTERN_ANALYSIS !== false;
const MODEL_TIMEOUT = 5000;

/**
 * Build a feature vector for a package (for rule-based or ML model)
 * @param {Object} params - timeline + name + scope + git activity + optional commitPatterns, nlpResult, crossPackageAnomaly, behavioralAnomaly
 * @returns {Object} Feature set
 */
function buildFeatureVector(params) {
  const {
    daysDifference = null,
    recentCommitCount = 0,
    scopeType = null,
    suspiciousPatternsCount = 0,
    registryName = null,
    commitPatterns = null,
    nlpResult = null,
    crossPackageAnomaly = null,
    behavioralAnomaly = null
  } = params;
  const timeline = analyzeTimeline({
    registryCreated: params.registryCreated ?? params.creationDate,
    firstCommitDate: params.firstCommitDate,
    recentCommitCount,
    scopeType
  });
  const features = {
    daysDifference: daysDifference ?? timeline.daysDifference ?? 365,
    recentCommitCount,
    scopePrivate: scopeType === 'PRIVATE' ? 1 : 0,
    suspiciousPatternsCount,
    timelineAnomaly: timeline.anomalyScore,
    registryIsNpm: registryName === 'npm' ? 1 : 0
  };
  if (commitPatterns) {
    features.authorCount = commitPatterns.authorCount ?? 0;
    features.totalCommitCount = commitPatterns.totalCommitCount ?? 0;
    features.dominantAuthorShare = commitPatterns.dominantAuthorShare ?? 0;
    features.commitPatternAnomaly = commitPatternAnomalyScore(commitPatterns);
    features.branchCount = commitPatterns.branchCount ?? 0;
    features.recentCommitCount90d = commitPatterns.recentCommitCount90d ?? 0;
    if (commitPatterns.messageAnomalyScore != null) features.messageAnomalyScore = commitPatterns.messageAnomalyScore;
    if (commitPatterns.diffAnomalyScore != null) features.diffAnomalyScore = commitPatterns.diffAnomalyScore;
  }
  if (nlpResult) {
    features.nlpSecurityScore = nlpResult.nlpSecurityScore ?? nlpResult.securityScore ?? 0;
    features.nlpSuspiciousCount = nlpResult.nlpSuspiciousCount ?? nlpResult.suspiciousPhrases?.length ?? 0;
  }
  if (crossPackageAnomaly != null) features.crossPackageAnomaly = crossPackageAnomaly;
  if (behavioralAnomaly != null) features.behavioralAnomaly = behavioralAnomaly;
  return features;
}

/**
 * Compute a single threat score (0–1) from features using configurable ML weights
 * @param {Object} features - From buildFeatureVector
 * @param {Object} [weights] - Override PHASE2_DETECTION.ML_WEIGHTS
 * @returns {number} Score 0–1
 */
function computeThreatScore(features, weights = ML_WEIGHTS) {
  let score = 0;
  if (features.timelineAnomaly != null && weights.timelineAnomaly)
    score += weights.timelineAnomaly * features.timelineAnomaly;
  if (features.scopePrivate === 1 && weights.scopePrivate) score += weights.scopePrivate;
  if (features.suspiciousPatternsCount > 0 && weights.suspiciousPatterns)
    score += Math.min(weights.suspiciousPatterns, 0.1 * features.suspiciousPatternsCount * (weights.suspiciousPatterns / 0.2));
  if (weights.lowActivityRecent && features.recentCommitCount < 5 && features.daysDifference < 30)
    score += weights.lowActivityRecent;
  if (features.commitPatternAnomaly != null && weights.commitPatternAnomaly)
    score += weights.commitPatternAnomaly * features.commitPatternAnomaly;
  if (features.nlpSecurityScore != null && weights.nlpSecurityScore)
    score += weights.nlpSecurityScore * features.nlpSecurityScore;
  if (features.crossPackageAnomaly != null && weights.crossPackageAnomaly)
    score += weights.crossPackageAnomaly * features.crossPackageAnomaly;
  if (features.behavioralAnomaly != null && weights.behavioralAnomaly)
    score += weights.behavioralAnomaly * features.behavioralAnomaly;
  return Math.min(1, score);
}

/**
 * Call external ML model API (POST features, expect { score: 0-1 })
 * @param {string} url - Full URL (e.g. https://api.example.com/score)
 * @param {Object} features - Feature vector
 * @param {number} timeout - Ms
 * @returns {Promise<number|null>} Score 0-1 or null on error
 */
function fetchModelScoreFromUrl(url, features, timeout = MODEL_TIMEOUT) {
  return new Promise((resolve) => {
    const payload = JSON.stringify({ features });
    const u = new URL(url);
    const options = {
      hostname: u.hostname,
      port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
        'User-Agent': 'NullVoid-Security-Scanner/2.0'
      },
      timeout
    };
    const protocol = u.protocol === 'https:' ? https : http;
    const req = protocol.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const json = data ? JSON.parse(data) : null;
          const score = json != null && typeof json.score === 'number' ? json.score : null;
          resolve(score != null ? Math.max(0, Math.min(1, score)) : null);
        } catch {
          resolve(null);
        }
      });
    });
    req.on('error', () => resolve(null));
    req.setTimeout(timeout, () => {
      req.destroy();
      resolve(null);
    });
    req.write(payload);
    req.end();
  });
}

/**
 * Call local ML model module (exports score(features) => number)
 * @param {string} modulePath - Absolute path to .js module
 * @param {Object} features - Feature vector
 * @returns {Promise<number|null>} Score 0-1 or null on error
 */
async function getModelScoreFromPath(modulePath, features) {
  try {
    const absPath = path.isAbsolute(modulePath) ? modulePath : path.resolve(process.cwd(), modulePath);
    const mod = require(absPath);
    const fn = mod.score || mod.predict || mod.default;
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
 * @param {Object} features - Feature vector
 * @returns {Promise<number|null>} Score 0-1 or null
 */
async function computeThreatScoreFromModel(features) {
  if (ML_MODEL_URL) {
    const score = await fetchModelScoreFromUrl(ML_MODEL_URL, features);
    if (score != null) return score;
  }
  if (ML_MODEL_PATH) {
    const score = await getModelScoreFromPath(ML_MODEL_PATH, features);
    if (score != null) return score;
  }
  return null;
}

/**
 * Compute a predictive risk score (0–1) from features: potential future risk based on patterns
 * even when below threat threshold. Used to flag "watch" or "potential risk" separately.
 * @param {Object} features - From buildFeatureVector
 * @returns {number} Score 0–1
 */
function computePredictiveScore(features) {
  let s = 0;
  if (features.timelineAnomaly != null) s += 0.4 * features.timelineAnomaly;
  if (features.commitPatternAnomaly != null) s += 0.25 * features.commitPatternAnomaly;
  if (features.recentCommitCount < 5 && (features.daysDifference ?? 365) < 90) s += 0.15;
  if (features.nlpSecurityScore != null) s += 0.15 * features.nlpSecurityScore;
  if (features.crossPackageAnomaly != null) s += 0.05 * features.crossPackageAnomaly;
  return Math.min(1, s);
}

/**
 * Run Phase 2 ML-style detection: anomaly score + threat score (rule-based or model)
 * @param {Object} params - Same as dependency confusion + optional packagePath, commitPatterns
 * @returns {Promise<Object>} { enabled, anomalyScore, threatScore, aboveThreshold, predictiveScore, predictiveRisk, features, modelUsed }
 */
async function runMLDetection(params) {
  const enabled = ML_ENABLED;
  let commitPatterns = params.commitPatterns ?? null;
  if (COMMIT_PATTERN_ENABLED && params.packagePath && !commitPatterns)
    commitPatterns = analyzeCommitPatterns(params.packagePath);

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
    firstCommitDate: params.firstCommitDate,
    commitPatterns,
    nlpResult: params.nlpResult ?? null,
    crossPackageAnomaly: params.crossPackageAnomaly ?? null,
    behavioralAnomaly: params.behavioralAnomaly ?? null
  });

  let threatScore = null;
  let modelUsed = false;
  if (ML_MODEL_URL || ML_MODEL_PATH) {
    threatScore = await computeThreatScoreFromModel(features);
    if (threatScore != null) modelUsed = true;
  }
  if (threatScore == null) threatScore = computeThreatScore(features);

  const anomalyScore = timeline.anomalyScore;
  const aboveThreshold = enabled && (threatScore >= ANOMALY_THRESHOLD || anomalyScore >= ANOMALY_THRESHOLD);
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
    modelUsed
  };
}

module.exports = {
  buildFeatureVector,
  computeThreatScore,
  computePredictiveScore,
  computeThreatScoreFromModel,
  runMLDetection
};
