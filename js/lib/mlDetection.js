/**
 * ML Detection scaffold (Phase 2)
 *
 * Lightweight threat scoring from timeline + pattern + commit-pattern features.
 * Supports rule-based weights, commit pattern analysis, and pluggable ML model
 * (external API or local Node module).
 */

const path = require('path');
const https = require('https');
const { DEPENDENCY_CONFUSION_CONFIG } = require('./config');
const { analyzeTimeline } = require('./timelineAnalysis');
const { analyzeCommitPatterns, commitPatternAnomalyScore } = require('./commitPatternAnalysis');

const PHASE2 = DEPENDENCY_CONFUSION_CONFIG?.PHASE2_DETECTION ?? {};
const ML_ENABLED = PHASE2.ML_SCORING !== false;
const ANOMALY_THRESHOLD = PHASE2.ML_ANOMALY_THRESHOLD ?? 0.7;
const ML_WEIGHTS = PHASE2.ML_WEIGHTS ?? {
  timelineAnomaly: 0.5,
  scopePrivate: 0.2,
  suspiciousPatterns: 0.2,
  lowActivityRecent: 0.1,
  commitPatternAnomaly: 0.1
};
const ML_MODEL_URL = PHASE2.ML_MODEL_URL || null;
const ML_MODEL_PATH = PHASE2.ML_MODEL_PATH || null;
const COMMIT_PATTERN_ENABLED = PHASE2.COMMIT_PATTERN_ANALYSIS !== false;
const MODEL_TIMEOUT = 5000;

/**
 * Build a feature vector for a package (for rule-based or ML model)
 * @param {Object} params - timeline + name + scope + git activity + optional commitPatterns or packagePath
 * @returns {Object} Feature set
 */
function buildFeatureVector(params) {
  const {
    daysDifference = null,
    recentCommitCount = 0,
    scopeType = null,
    suspiciousPatternsCount = 0,
    registryName = null,
    commitPatterns = null
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
  }
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
    const req = https.request(options, (res) => {
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
 * Run Phase 2 ML-style detection: anomaly score + threat score (rule-based or model)
 * @param {Object} params - Same as dependency confusion + optional packagePath, commitPatterns
 * @returns {Promise<Object>} { enabled, anomalyScore, threatScore, aboveThreshold, features, modelUsed }
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
    commitPatterns
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
  return {
    enabled,
    anomalyScore,
    threatScore,
    aboveThreshold,
    features,
    modelUsed
  };
}

module.exports = {
  buildFeatureVector,
  computeThreatScore,
  computeThreatScoreFromModel,
  runMLDetection
};
