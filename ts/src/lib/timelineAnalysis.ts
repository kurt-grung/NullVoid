/**
 * Enhanced Timeline Analysis
 *
 * Builds structured timeline events from git + registry data and computes
 * statistical anomaly scores for dependency confusion detection. Feeds into
 * ML detection module.
 */

import { DEPENDENCY_CONFUSION_CONFIG } from './config';

const THRESHOLDS = DEPENDENCY_CONFUSION_CONFIG.TIMELINE_THRESHOLDS;

export interface TimelineEvent {
  type: string;
  date: Date;
  label: string;
}

export interface TimelineParams {
  registryCreated?: Date | string | null | undefined;
  registryModified?: Date | string | null | undefined;
  creationDate?: Date | string | null | undefined;
  firstCommitDate?: Date | string | null | undefined;
  recentCommitCount?: number | undefined;
  scopeType?: 'PRIVATE' | 'PUBLIC' | 'UNKNOWN' | null | undefined;
}

export interface TimelineAnalysisResult {
  events: TimelineEvent[];
  daysDifference: number | null;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  anomalyScore: number;
}

/**
 * Build a timeline event list for a package (registry + git)
 */
export function buildTimelineEvents(params: TimelineParams): TimelineEvent[] {
  const { registryCreated, registryModified, firstCommitDate } = params;
  const events: TimelineEvent[] = [];
  if (registryCreated) {
    events.push({
      type: 'registry_created',
      date: new Date(registryCreated),
      label: 'Registry package created',
    });
  }
  if (registryModified) {
    events.push({
      type: 'registry_modified',
      date: new Date(registryModified),
      label: 'Registry package modified',
    });
  }
  if (firstCommitDate) {
    events.push({
      type: 'first_commit',
      date: new Date(firstCommitDate),
      label: 'First git commit',
    });
  }
  events.sort((a, b) => a.date.getTime() - b.date.getTime());
  return events;
}

/**
 * Compute days between two dates
 */
export function daysBetween(a: Date | string, b: Date | string): number {
  const d1 = new Date(a);
  const d2 = new Date(b);
  return Math.abs(d1.getTime() - d2.getTime()) / (1000 * 60 * 60 * 24);
}

/**
 * Rule-based timeline risk (existing logic, kept for compatibility)
 */
export function getTimelineRiskLevel(
  daysDifference: number
): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
  if (daysDifference <= THRESHOLDS.CRITICAL) return 'CRITICAL';
  if (daysDifference <= THRESHOLDS.HIGH_RISK) return 'HIGH';
  if (daysDifference <= THRESHOLDS.SUSPICIOUS) return 'MEDIUM';
  return 'LOW';
}

/**
 * Statistical anomaly score for timeline (0–1). Higher = more anomalous.
 */
export function timelineAnomalyScore(params: {
  daysDifference?: number;
  recentCommitCount?: number;
  hasScopeConflict?: boolean;
}): number {
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
 */
export function analyzeTimeline(params: TimelineParams): TimelineAnalysisResult {
  const events = buildTimelineEvents(params);
  const registryCreated = params.registryCreated ?? params.creationDate;
  const firstCommit = params.firstCommitDate;
  const daysDifference =
    registryCreated && firstCommit ? daysBetween(registryCreated, firstCommit) : null;
  const riskLevel = daysDifference != null ? getTimelineRiskLevel(daysDifference) : 'LOW';
  const anomalyScore = timelineAnomalyScore({
    daysDifference: daysDifference ?? 365,
    recentCommitCount: params.recentCommitCount ?? 0,
    hasScopeConflict: params.scopeType === 'PRIVATE',
  });
  return {
    events,
    daysDifference,
    riskLevel,
    anomalyScore,
  };
}
