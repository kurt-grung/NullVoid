/**
 * Dependency Confusion Detection Module
 *
 * Detects potential dependency confusion attacks by analyzing:
 * - Git history vs npm registry creation dates
 * - Scope ownership and namespace conflicts
 * - Package name similarity patterns
 * - Timeline-based threat indicators (enhanced timeline, ML scoring)
 */

import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';
import { Threat, createThreat } from '../types/core';
import { DEPENDENCY_CONFUSION_CONFIG, DETECTION_PATTERNS } from './config';
import { getPackageCreationDateMulti } from './registries';
import { analyzeTimeline } from './timelineAnalysis';
import { runMLDetection } from './mlDetection';
import { runNlpAnalysis } from './nlpAnalysis';
import { runCommunityAnalysis } from './communityAnalysis';
import { getTrustScore } from './trustNetwork';
import { computeBehavioralAnomaly, computeCrossPackageAnomaly } from './anomalyDetection';
import { NLP_CONFIG, COMMUNITY_CONFIG, TRUST_CONFIG } from './config';

export interface PackageInfo {
  name: string;
  version: string;
  creationDate: string | null;
  gitHistory: GitHistory;
  analysis: PackageNameAnalysis;
}

export interface GitHistory {
  commits: Array<{ date: string; message: string; author: string }>;
  totalCommits: number;
  firstCommitDate?: Date;
  recentCommitCount?: number;
  hasGitHistory?: boolean;
  error?: string;
}

export interface PackageNameAnalysis {
  isScoped: boolean;
  scope: string | null;
  unscopedName: string;
  suspiciousPatterns: string[];
  similarityScore: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH';
  scopeType?: 'PRIVATE' | 'PUBLIC' | 'UNKNOWN';
}

export interface DependencyConfusionOptions {
  checkTimeline?: boolean;
  checkSimilarity?: boolean;
  checkScope?: boolean;
  checkGitActivity?: boolean;
}

export interface PackageToAnalyze {
  name: string;
  path: string;
}

/**
 * Calculate string similarity using Levenshtein distance
 */
export function calculateSimilarity(str1: string, str2: string): number {
  const longer = str1.length > str2.length ? str1 : str2;
  const shorter = str1.length > str2.length ? str2 : str1;

  if (longer.length === 0) return 1.0;

  const distance = levenshteinDistance(longer, shorter);
  return (longer.length - distance) / longer.length;
}

/**
 * Calculate Levenshtein distance between two strings
 */
export function levenshteinDistance(str1: string, str2: string): number {
  if (str1.length === 0) return str2.length;
  if (str2.length === 0) return str1.length;

  const len1 = str1.length;
  const len2 = str2.length;
  const matrix: number[][] = Array.from({ length: len2 + 1 }, () => Array(len1 + 1).fill(0));

  for (let i = 0; i <= len2; i++) {
    matrix[i]![0] = i;
  }
  for (let j = 0; j <= len1; j++) {
    matrix[0]![j] = j;
  }

  for (let i = 1; i <= len2; i++) {
    for (let j = 1; j <= len1; j++) {
      const cost = str2.charAt(i - 1) === str1.charAt(j - 1) ? 0 : 1;
      matrix[i]![j] = Math.min(
        matrix[i - 1]![j]! + 1,
        matrix[i]![j - 1]! + 1,
        matrix[i - 1]![j - 1]! + cost
      );
    }
  }

  return matrix[len2]![len1]!;
}

/**
 * Get package creation date from npm registry
 */
export async function getPackageCreationDate(packageName: string): Promise<Date | null> {
  try {
    const response = await fetch(
      `${DEPENDENCY_CONFUSION_CONFIG.REGISTRY_ENDPOINTS.npm}/${encodeURIComponent(packageName)}`
    );
    if (!response.ok) return null;
    const data = (await response.json()) as Record<string, unknown>;
    const created = (data['time'] as Record<string, unknown>)?.['created'] as string | undefined;
    return created ? new Date(created) : null;
  } catch {
    return null;
  }
}

/**
 * Get git history for a package/directory (sync, uses execSync)
 */
export function getGitHistorySync(packagePath: string): GitHistory {
  try {
    const firstCommit = execSync('git log --reverse -1 --format="%H %ci" -- .', {
      cwd: packagePath,
      encoding: 'utf8',
      timeout: 10000,
    }).trim();

    if (!firstCommit) {
      return {
        commits: [],
        totalCommits: 0,
        hasGitHistory: false,
      };
    }

    const parts = firstCommit.split(/\s+/);
    const dateStr = parts.slice(1).join(' ');
    const firstCommitDate = new Date(dateStr);

    const recentCommitsStr = execSync('git log --format="%ci" --since="1 year ago" -- . | wc -l', {
      cwd: packagePath,
      encoding: 'utf8',
      timeout: 5000,
    }).trim();
    const recentCommitCount = parseInt(recentCommitsStr, 10) || 0;

    return {
      commits: [{ date: dateStr, message: '', author: '' }],
      totalCommits: 1,
      firstCommitDate,
      recentCommitCount,
      hasGitHistory: true,
    };
  } catch {
    return {
      commits: [],
      totalCommits: 0,
      hasGitHistory: false,
    };
  }
}

/**
 * Analyze package name for suspicious patterns
 */
export function analyzePackageName(packageName: string): PackageNameAnalysis {
  const isScoped = packageName.startsWith('@');
  const scope = isScoped ? (packageName.split('/')[0] ?? null) : null;
  const unscopedName = isScoped ? (packageName.split('/')[1] ?? packageName) : packageName;

  const suspiciousPatterns: string[] = [];

  DEPENDENCY_CONFUSION_CONFIG.SUSPICIOUS_NAME_PATTERNS.forEach((pattern, index) => {
    if (pattern.test(packageName)) {
      suspiciousPatterns.push(`Pattern ${index + 1}`);
    }
  });

  const popularPackages = DETECTION_PATTERNS.POPULAR_PACKAGES;
  let maxSimilarity = 0;
  popularPackages.forEach((popular) => {
    const similarity = calculateSimilarity(unscopedName, popular);
    if (similarity > maxSimilarity) maxSimilarity = similarity;
  });

  const riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' =
    suspiciousPatterns.length > 0 ? 'HIGH' : maxSimilarity > 0.8 ? 'MEDIUM' : 'LOW';

  let scopeType: 'PRIVATE' | 'PUBLIC' | 'UNKNOWN' = 'UNKNOWN';
  if (isScoped) {
    const isPrivateScope = DEPENDENCY_CONFUSION_CONFIG.SCOPE_PATTERNS.PRIVATE_SCOPES.some((p) =>
      p.test(packageName)
    );
    const isPublicScope = DEPENDENCY_CONFUSION_CONFIG.SCOPE_PATTERNS.PUBLIC_SCOPES.some((p) =>
      p.test(packageName)
    );
    if (isPrivateScope) scopeType = 'PRIVATE';
    else if (isPublicScope) scopeType = 'PUBLIC';
  } else {
    scopeType = 'PUBLIC';
  }

  return {
    isScoped,
    scope,
    unscopedName,
    suspiciousPatterns,
    similarityScore: maxSimilarity,
    riskLevel,
    scopeType,
  };
}

/**
 * Detect dependency confusion threats (with package path for full ML pipeline)
 */
export async function detectDependencyConfusionWithPath(
  packageName: string,
  packagePath: string
): Promise<Threat[]> {
  const threats: Threat[] = [];
  const mlCfg = (DEPENDENCY_CONFUSION_CONFIG as { ML_DETECTION?: { MULTI_REGISTRY?: boolean } })
    .ML_DETECTION;
  const useMultiRegistry = mlCfg?.MULTI_REGISTRY !== false;

  try {
    let creationDate: Date | null = null;
    let registryName = 'npm';

    if (useMultiRegistry) {
      const multi = await getPackageCreationDateMulti(packageName);
      if (multi?.created) {
        creationDate = multi.created;
        registryName = multi.registryName ?? 'npm';
      }
    }
    if (!creationDate) {
      creationDate = await getPackageCreationDate(packageName);
    }
    if (!creationDate) return threats;

    const gitHistory = getGitHistorySync(packagePath);
    if (!gitHistory.hasGitHistory || !gitHistory.firstCommitDate) {
      return threats;
    }

    const nameAnalysis = analyzePackageName(packageName);
    const timelineResult = analyzeTimeline({
      registryCreated: creationDate,
      firstCommitDate: gitHistory.firstCommitDate,
      recentCommitCount: gitHistory.recentCommitCount ?? 0,
      scopeType: nameAnalysis.scopeType ?? null,
    });
    const daysDifference = timelineResult.daysDifference ?? 0;
    const timelineRisk = timelineResult.riskLevel;

    let nlpResult = null;
    let communityResult = null;
    let crossPackageAnomaly: number | null = null;
    let behavioralAnomaly: number | null = null;

    let pkgFeatures: {
      scriptCount: number;
      scriptTotalLength: number;
      hasPostinstall: boolean;
      postinstallLength: number;
      dependencyCount: number;
      devDependencyCount: number;
      rareDependencyCount: number;
    } | null = null;

    try {
      const pkgPath = path.join(packagePath, 'package.json');
      if (fs.existsSync(pkgPath)) {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')) as Record<string, unknown>;
        const scripts = (pkg['scripts'] as Record<string, string>) || {};
        const scriptKeys = Object.keys(scripts);
        const postinstall = scripts['postinstall'] ?? scripts['install'];
        pkgFeatures = {
          scriptCount: scriptKeys.length,
          scriptTotalLength: scriptKeys.reduce((sum, k) => sum + (scripts[k] ?? '').length, 0),
          hasPostinstall: !!postinstall,
          postinstallLength: postinstall ? postinstall.length : 0,
          dependencyCount: Object.keys((pkg['dependencies'] as object) || {}).length,
          devDependencyCount: Object.keys((pkg['devDependencies'] as object) || {}).length,
          rareDependencyCount: 0,
        };
        behavioralAnomaly = computeBehavioralAnomaly(pkgFeatures);
        crossPackageAnomaly = computeCrossPackageAnomaly(pkgFeatures, []);
      }
    } catch {
      /* ignore */
    }

    let version = 'latest';
    try {
      const pkgPath = path.join(packagePath, 'package.json');
      if (fs.existsSync(pkgPath)) {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')) as Record<string, unknown>;
        version = (pkg['version'] as string) || 'latest';
      }
    } catch {
      /* ignore */
    }

    if (NLP_CONFIG.ENABLED) {
      try {
        nlpResult = await runNlpAnalysis(packageName, version, NLP_CONFIG);
      } catch {
        /* ignore */
      }
    }
    if (COMMUNITY_CONFIG.ENABLED) {
      try {
        communityResult = await runCommunityAnalysis(packageName, version, COMMUNITY_CONFIG);
      } catch {
        /* ignore */
      }
    }

    let trustScore: number | null = null;
    if (TRUST_CONFIG.ENABLED) {
      try {
        trustScore = await getTrustScore(packageName, version);
      } catch {
        /* ignore */
      }
    }

    const mlResult = await runMLDetection({
      creationDate,
      firstCommitDate: gitHistory.firstCommitDate,
      recentCommitCount: gitHistory.recentCommitCount ?? 0,
      scopeType: nameAnalysis.scopeType ?? null,
      suspiciousPatternsCount: nameAnalysis.suspiciousPatterns?.length ?? 0,
      registryName,
      packagePath,
      nlpResult,
      communityResult,
      trustScore,
      crossPackageAnomaly,
      behavioralAnomaly,
    });

    if (timelineRisk !== 'LOW') {
      const confidence =
        mlResult.enabled && mlResult.aboveThreshold
          ? Math.min(95, 70 + Math.round(mlResult.threatScore * 25))
          : Math.min(95, Math.max(0, 60 + (30 - daysDifference) * 2));
      threats.push(
        createThreat(
          'DEPENDENCY_CONFUSION_TIMELINE',
          `Package creation date suspiciously close to git history (${Math.round(daysDifference)} days)`,
          packagePath,
          'package.json',
          timelineRisk === 'CRITICAL' ? 'CRITICAL' : timelineRisk === 'HIGH' ? 'HIGH' : 'MEDIUM',
          `Package created: ${creationDate.toISOString()}, First git commit: ${gitHistory.firstCommitDate!.toISOString()}${registryName !== 'npm' ? ` (registry: ${registryName})` : ''}`,
          {
            package: packageName,
            confidence: confidence / 100,
            creationDate: creationDate.toISOString(),
            firstCommitDate: gitHistory.firstCommitDate!.toISOString(),
            daysDifference: Math.round(daysDifference),
            timelineRisk,
            registryName,
            ...(mlResult.enabled && {
              mlAnomalyScore: mlResult.anomalyScore,
              mlThreatScore: mlResult.threatScore,
            }),
            ...(mlResult.modelUsed && { mlModelUsed: true }),
            ...(mlResult.features?.commitPatternAnomaly != null && {
              commitPatternAnomaly: mlResult.features.commitPatternAnomaly,
            }),
          }
        )
      );
    }

    if (timelineRisk === 'LOW' && mlResult.enabled && mlResult.aboveThreshold) {
      threats.push(
        createThreat(
          'DEPENDENCY_CONFUSION_ML_ANOMALY',
          'ML anomaly score indicates potential dependency confusion risk',
          packagePath,
          'package.json',
          mlResult.threatScore >= 0.8 ? 'HIGH' : 'MEDIUM',
          `Anomaly score: ${(mlResult.anomalyScore * 100).toFixed(0)}%, Threat score: ${(mlResult.threatScore * 100).toFixed(0)}%`,
          {
            package: packageName,
            confidence: mlResult.threatScore * 0.9,
            mlAnomalyScore: mlResult.anomalyScore,
            mlThreatScore: mlResult.threatScore,
            registryName,
            ...(mlResult.modelUsed && { mlModelUsed: true }),
            ...(mlResult.features?.commitPatternAnomaly != null && {
              commitPatternAnomaly: mlResult.features.commitPatternAnomaly,
            }),
          }
        )
      );
    }

    if (
      timelineRisk === 'LOW' &&
      mlResult.enabled &&
      mlResult.predictiveRisk &&
      !mlResult.aboveThreshold
    ) {
      threats.push(
        createThreat(
          'DEPENDENCY_CONFUSION_PREDICTIVE_RISK',
          'Predictive risk: patterns suggest potential dependency confusion risk',
          packagePath,
          'package.json',
          'LOW',
          `Predictive score: ${(mlResult.predictiveScore * 100).toFixed(0)}% (anomaly: ${(mlResult.anomalyScore * 100).toFixed(0)}%)`,
          {
            package: packageName,
            confidence: mlResult.predictiveScore * 0.6,
            predictiveScore: mlResult.predictiveScore,
            mlAnomalyScore: mlResult.anomalyScore,
            registryName,
            ...(mlResult.features?.commitPatternAnomaly != null && {
              commitPatternAnomaly: mlResult.features.commitPatternAnomaly,
            }),
          }
        )
      );
    }

    if (nameAnalysis.suspiciousPatterns.length > 0) {
      threats.push(
        createThreat(
          'DEPENDENCY_CONFUSION_PATTERN',
          'Package name follows suspicious naming patterns',
          packagePath,
          'package.json',
          nameAnalysis.scopeType === 'PRIVATE' ? 'HIGH' : 'MEDIUM',
          `Suspicious patterns: ${nameAnalysis.suspiciousPatterns.join(', ')}`,
          {
            package: packageName,
            confidence: 0.75,
            suspiciousPatterns: nameAnalysis.suspiciousPatterns,
            scopeType: nameAnalysis.scopeType,
            isScoped: nameAnalysis.isScoped,
          }
        )
      );
    }

    if (nameAnalysis.scopeType === 'PRIVATE') {
      threats.push(
        createThreat(
          'DEPENDENCY_CONFUSION_SCOPE',
          'Private scope package may be vulnerable to dependency confusion',
          packagePath,
          'package.json',
          'HIGH',
          `Private scope '@${nameAnalysis.scope}' detected. Ensure proper npm registry configuration.`,
          {
            package: packageName,
            confidence: 0.85,
            scope: nameAnalysis.scope,
            scopeType: nameAnalysis.scopeType,
            unscopedName: nameAnalysis.unscopedName,
          }
        )
      );
    }

    if ((gitHistory.recentCommitCount ?? 0) < 5 && daysDifference > 30) {
      threats.push(
        createThreat(
          'DEPENDENCY_CONFUSION_ACTIVITY',
          'Low git activity may indicate typosquatting or abandoned package',
          packagePath,
          'package.json',
          'MEDIUM',
          `Only ${gitHistory.recentCommitCount ?? 0} commits in the last year`,
          {
            package: packageName,
            confidence: 0.6,
            recentCommitCount: gitHistory.recentCommitCount ?? 0,
            daysDifference: Math.round(daysDifference),
          }
        )
      );
    }
  } catch (error) {
    threats.push(
      createThreat(
        'DEPENDENCY_CONFUSION_ERROR',
        `Error analyzing dependency confusion: ${error instanceof Error ? error.message : String(error)}`,
        packagePath,
        'package.json',
        'LOW',
        (error as Error).stack ?? '',
        {
          package: packageName,
          confidence: 0.1,
          error: error instanceof Error ? error.message : String(error),
        }
      )
    );
  }

  return threats;
}

/**
 * Detect dependency confusion (legacy single-package, no path)
 */
export async function detectDependencyConfusion(packageName: string): Promise<Threat[]> {
  return analyzeDependencyConfusion([{ name: packageName, path: process.cwd() }]);
}

/**
 * Analyze dependency confusion for multiple packages
 */
export async function analyzeDependencyConfusion(packages: PackageToAnalyze[]): Promise<Threat[]> {
  const allThreats: Threat[] = [];

  for (const pkg of packages) {
    if (pkg.name && pkg.path) {
      try {
        const threats = await detectDependencyConfusionWithPath(pkg.name, pkg.path);
        allThreats.push(...threats);
      } catch (error) {
        allThreats.push(
          createThreat(
            'DEPENDENCY_CONFUSION_ERROR',
            `Error analyzing dependency confusion: ${error instanceof Error ? error.message : String(error)}`,
            pkg.path,
            'package.json',
            'LOW',
            'Failed to analyze package for dependency confusion',
            {
              package: pkg.name,
              confidence: 0.1,
              error: error instanceof Error ? error.message : String(error),
            }
          )
        );
      }
    }
  }

  return allThreats;
}

/**
 * Get git history (async wrapper for compatibility)
 */
export async function getGitHistory(packagePath?: string): Promise<GitHistory> {
  if (packagePath) {
    return Promise.resolve(getGitHistorySync(packagePath));
  }
  return {
    commits: [],
    totalCommits: 0,
    hasGitHistory: false,
  };
}

/**
 * Dependency Confusion Analyzer class
 */
export class DependencyConfusionAnalyzer {
  async analyze(packageName: string): Promise<Threat[]> {
    return analyzeDependencyConfusion([{ name: packageName, path: process.cwd() }]);
  }

  async analyzeMultiple(packageNames: string[]): Promise<Threat[]> {
    const packages = packageNames.map((name) => ({
      name,
      path: process.cwd(),
    }));
    return analyzeDependencyConfusion(packages);
  }

  async analyzePackages(packages: PackageToAnalyze[]): Promise<Threat[]> {
    return analyzeDependencyConfusion(packages);
  }
}
