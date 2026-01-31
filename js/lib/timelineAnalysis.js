/**
 * Enhanced Timeline Analysis (Phase 2)
 *
 * Builds structured timeline events from git + registry data and computes
 * statistical anomaly scores for dependency confusion detection. Feeds into
 * ML detection module.
 */

const { DEPENDENCY_CONFUSION_CONFIG } = require('./config');

const TIMELINE_THRESHOLDS = DEPENDENCY_CONFUSION_CONFIG?.TIMELINE_THRESHOLDS ?? {
  SUSPICIOUS: 30,
  HIGH_RISK: 7,
  CRITICAL: 1
};

/**
 * Build a timeline event list for a package (registry + git)
 * @param {Object} params - { registryCreated, registryModified, firstCommitDate, recentCommitCount }
 * @returns {Array<{ type: string, date: Date, label: string }>} Sorted events
 */
function buildTimelineEvents(params) {
  const { registryCreated, registryModified, firstCommitDate, recentCommitCount } = params;
  const events = [];
  if (registryCreated)
    events.push({ type: 'registry_created', date: new Date(registryCreated), label: 'Registry package created' });
  if (registryModified)
    events.push({ type: 'registry_modified', date: new Date(registryModified), label: 'Registry package modified' });
  if (firstCommitDate)
    events.push({ type: 'first_commit', date: new Date(firstCommitDate), label: 'First git commit' });
  events.sort((a, b) => a.date - b.date);
  return events;
}

/**
 * Compute days between two dates
 * @param {Date|string} a
 * @param {Date|string} b
 * @returns {number} Absolute days difference
 */
function daysBetween(a, b) {
  const d1 = new Date(a);
  const d2 = new Date(b);
  return Math.abs(d1 - d2) / (1000 * 60 * 60 * 24);
}

/**
 * Rule-based timeline risk (existing logic, kept for compatibility)
 * @param {number} daysDifference - Days between registry creation and first commit
 * @returns {'LOW'|'MEDIUM'|'HIGH'|'CRITICAL'}
 */
function getTimelineRiskLevel(daysDifference) {
  if (daysDifference <= TIMELINE_THRESHOLDS.CRITICAL) return 'CRITICAL';
  if (daysDifference <= TIMELINE_THRESHOLDS.HIGH_RISK) return 'HIGH';
  if (daysDifference <= TIMELINE_THRESHOLDS.SUSPICIOUS) return 'MEDIUM';
  return 'LOW';
}

/**
 * Statistical anomaly score for timeline (0–1). Higher = more anomalous.
 * Uses: days between registry creation and first commit, and low activity.
 * @param {Object} params - { daysDifference, recentCommitCount, hasScopeConflict }
 * @returns {number} Anomaly score 0–1
 */
function timelineAnomalyScore(params) {
  const { daysDifference = 365, recentCommitCount = 0, hasScopeConflict = false } = params;
  let score = 0;
  // Very recent registry vs old repo = high anomaly
  if (daysDifference <= 1) score += 0.5;
  else if (daysDifference <= 7) score += 0.35;
  else if (daysDifference <= 30) score += 0.2;
  // Low git activity = higher anomaly
  if (recentCommitCount < 1) score += 0.2;
  else if (recentCommitCount < 5) score += 0.1;
  if (hasScopeConflict) score += 0.2;
  return Math.min(1, score);
}

/**
 * Full timeline analysis result for a package
 * @param {Object} params - registry + git data
 * @returns {Object} { events, daysDifference, riskLevel, anomalyScore }
 */
function analyzeTimeline(params) {
  const events = buildTimelineEvents(params);
  const registryCreated = params.registryCreated ?? params.creationDate;
  const firstCommit = params.firstCommitDate;
  const daysDifference = registryCreated && firstCommit
    ? daysBetween(registryCreated, firstCommit)
    : null;
  const riskLevel = daysDifference != null ? getTimelineRiskLevel(daysDifference) : 'LOW';
  const anomalyScore = timelineAnomalyScore({
    daysDifference: daysDifference ?? 365,
    recentCommitCount: params.recentCommitCount ?? 0,
    hasScopeConflict: params.scopeType === 'PRIVATE'
  });
  return {
    events,
    daysDifference,
    riskLevel,
    anomalyScore
  };
}

module.exports = {
  buildTimelineEvents,
  daysBetween,
  getTimelineRiskLevel,
  timelineAnomalyScore,
  analyzeTimeline
};
