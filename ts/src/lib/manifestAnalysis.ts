/**
 * Per-package.json analysis: dependency name/version heuristics, IoC provider
 * queries, NLP analysis and dependency-confusion / ML scoring.
 *
 * Budgets (IoC queries, dependency-confusion packages) are per scan, so the
 * caller passes one ScanBudgets object through every manifest.
 */

import * as fs from 'fs';
import * as path from 'path';
import type { ScanOptions, Threat } from '../types/core';
import type { IoCProviderName } from '../types/ioc-types';
import { createLogger } from './logger';
import { queryIoCProviders, mergeIoCThreats } from './iocScanIntegration';
import { analyzeDependencyConfusion } from './dependencyConfusion';
import { NLP_CONFIG, SCAN_COVERAGE_LIMITS } from './config';
import { runNlpAnalysis } from './nlpAnalysis';

const logger = createLogger('scan');

const SUSPICIOUS_PATTERNS = {
  dependencies: ['http://.*', 'git://.*', 'file://.*'],
  keywords: ['malware', 'virus', 'trojan', 'backdoor'],
};

/** Threat types that indicate malware in code (vs meta/scan errors) */
const CODE_THREAT_TYPES = new Set([
  'MALICIOUS_CODE',
  'WALLET_HIJACKING',
  'OBFUSCATED_CODE',
  'SUSPICIOUS_SCRIPT',
  'CRYPTO_MINING',
  'SUPPLY_CHAIN_ATTACK',
  'DATA_EXFILTRATION',
  'PATH_TRAVERSAL',
  'COMMAND_INJECTION',
  'DYNAMIC_REQUIRE',
  'SUSPICIOUS_MODULE',
  'OBFUSCATED_IOC',
  'SUSPICIOUS_DEPENDENCY',
  'MALICIOUS_CODE_STRUCTURE',
  'SUSPICIOUS_FILE',
  'DEPENDENCY_CONFUSION',
  'DEPENDENCY_CONFUSION_PATTERN',
  'DEPENDENCY_CONFUSION_ML_ANOMALY',
  'DEPENDENCY_CONFUSION_TIMELINE',
  'DEPENDENCY_CONFUSION_SCOPE',
  'DEPENDENCY_CONFUSION_ACTIVITY',
  'DEPENDENCY_CONFUSION_PREDICTIVE_RISK',
]);

export function isCodeThreatType(type: string): boolean {
  return (
    CODE_THREAT_TYPES.has(type) ||
    type.startsWith('ENHANCED_RULE_') ||
    type.startsWith('AGGREGATE_')
  );
}

/** Nearest ancestor directory (inclusive) that holds a package.json. */
export function findPackageRoot(filePath: string): string | null {
  let dir = path.isAbsolute(filePath)
    ? path.dirname(filePath)
    : path.resolve(path.dirname(filePath));
  const root = path.parse(dir).root;
  while (dir && dir !== root) {
    if (fs.existsSync(path.join(dir, 'package.json'))) return dir;
    dir = path.dirname(dir);
  }
  return null;
}

export interface PackageRef {
  name: string;
  path: string;
}

/** Per-scan counters for the coverage caps reported in scanTruncations. */
export interface ScanBudgets {
  iocQueriesUsed: number;
  iocQueriesEligible: number;
  depConfusionProcessed: number;
  depConfusionEligible: number;
}

export function createScanBudgets(): ScanBudgets {
  return {
    iocQueriesUsed: 0,
    iocQueriesEligible: 0,
    depConfusionProcessed: 0,
    depConfusionEligible: 0,
  };
}

export interface ManifestAnalysis {
  threats: Threat[];
  /** Number of declared dependencies (counted towards packagesScanned) */
  dependencyCount: number;
  /** Packages that went through dependency-confusion / ML analysis */
  packagesAnalyzed: PackageRef[];
  /** Package roots that produced a code-level dependency-confusion threat */
  threatPackageRoots: Set<string>;
}

function parseProviderNames(spec: string | undefined): IoCProviderName[] | undefined {
  if (!spec) return undefined;
  return spec
    .split(',')
    .map((p) => p.trim().toLowerCase())
    .filter((p) => p === 'snyk' || p === 'npm' || p === 'ghsa' || p === 'cve') as IoCProviderName[];
}

function dependencyHeuristics(
  depName: string,
  depVersion: string,
  packageJsonPath: string
): Threat[] {
  const threats: Threat[] = [];
  // A keyword in a dependency *name* ("virus-scan", "clamav", "backdoor-detector")
  // is a weak signal on its own, so it is reported at LOW and only surfaces with --all.
  if (SUSPICIOUS_PATTERNS.keywords.some((k) => depName.toLowerCase().includes(k.toLowerCase()))) {
    threats.push({
      type: 'SUSPICIOUS_DEPENDENCY',
      message: `Suspicious dependency name: ${depName}`,
      filePath: packageJsonPath,
      filename: 'package.json',
      severity: 'LOW',
      details: `Dependency "${depName}" contains a suspicious keyword in its name`,
      confidence: 0.3,
    });
  }
  if (SUSPICIOUS_PATTERNS.dependencies.some((pattern) => depVersion.match(new RegExp(pattern)))) {
    threats.push({
      type: 'SUSPICIOUS_DEPENDENCY',
      message: `Suspicious dependency version: ${depName}@${depVersion}`,
      filePath: packageJsonPath,
      filename: 'package.json',
      severity: 'HIGH',
      details: `Dependency "${depName}" has suspicious version pattern: ${depVersion}`,
      confidence: 0.8,
    });
  }
  return threats;
}

function nlpThreat(
  depName: string,
  cleanVersion: string,
  packageJsonPath: string,
  options: ScanOptions
): Promise<Threat[]> {
  return runNlpAnalysis(depName, cleanVersion, NLP_CONFIG)
    .then((nlpResult): Threat[] => {
      if (
        nlpResult &&
        nlpResult.nlpSecurityScore >= 0.5 &&
        nlpResult.suspiciousPhrases.length > 0
      ) {
        return [
          {
            type: 'NLP_SECURITY_INDICATOR',
            message: `NLP analysis: security indicators in ${depName} docs/issues`,
            filePath: packageJsonPath,
            filename: 'package.json',
            severity: nlpResult.nlpSecurityScore >= 0.7 ? 'MEDIUM' : 'LOW',
            details: `Security score: ${(nlpResult.nlpSecurityScore * 100).toFixed(0)}%. Suspicious: ${nlpResult.suspiciousPhrases.slice(0, 3).join(', ')}`,
            confidence: Math.round(nlpResult.nlpSecurityScore * 80),
          },
        ];
      }
      return [];
    })
    .catch((err: Error) => {
      if (options.verbose) logger.warn(`NLP query failed for ${depName}: ${err.message}`);
      return [];
    });
}

/** Root package plus installed dependencies, within the per-scan cap. */
function packagesForDependencyConfusion(
  packageDir: string,
  packageJson: Record<string, unknown>,
  dependencies: Record<string, string>,
  budgets: ScanBudgets
): PackageRef[] {
  const packagesToAnalyze: PackageRef[] = [];
  let eligible = 0;
  const rootName = packageJson['name'] as string | undefined;
  const limit = SCAN_COVERAGE_LIMITS.DEPENDENCY_CONFUSION_PACKAGES;
  if (rootName) {
    eligible += 1;
    packagesToAnalyze.push({ name: rootName, path: packageDir });
  }
  const nodeModulesPath = path.join(packageDir, 'node_modules');
  if (fs.existsSync(nodeModulesPath)) {
    for (const depName of Object.keys(dependencies)) {
      const depPath = path.join(nodeModulesPath, depName);
      if (fs.existsSync(depPath)) {
        eligible += 1;
        if (packagesToAnalyze.length < limit)
          packagesToAnalyze.push({ name: depName, path: depPath });
      }
    }
  }
  budgets.depConfusionEligible += eligible;
  budgets.depConfusionProcessed += packagesToAnalyze.length;
  return packagesToAnalyze;
}

/**
 * Analyze one package.json: heuristics on declared dependencies, IoC/NLP
 * lookups (within budget) and dependency-confusion / ML analysis.
 * Returns null when the directory has no package.json or it cannot be parsed.
 */
export async function analyzeManifest(
  packageDir: string,
  options: ScanOptions,
  budgets: ScanBudgets
): Promise<ManifestAnalysis | null> {
  const packageJsonPath = path.join(packageDir, 'package.json');
  if (!fs.existsSync(packageJsonPath)) return null;

  let packageJson: Record<string, unknown>;
  try {
    packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8')) as Record<string, unknown>;
  } catch (error) {
    if (options.verbose) {
      logger.warn(`Warning: Could not parse package.json: ${(error as Error).message}`);
    }
    return null;
  }

  const dependencies: Record<string, string> = {
    ...((packageJson['dependencies'] as Record<string, string>) || {}),
    ...(options.includeDevDependencies !== false
      ? (packageJson['devDependencies'] as Record<string, string>) || {}
      : {}),
  };
  const result: ManifestAnalysis = {
    threats: [],
    dependencyCount: Object.keys(dependencies).length,
    packagesAnalyzed: [],
    threatPackageRoots: new Set(),
  };
  if (result.dependencyCount === 0) return result;

  const dependencyThreats: Threat[] = [];
  const iocQueries: Promise<Threat[]>[] = [];
  const nlpQueries: Promise<Threat[]>[] = [];
  const providerNames = parseProviderNames(options.iocProviders);

  for (const [depName, depVersion] of Object.entries(dependencies)) {
    if (typeof depVersion !== 'string') continue;
    dependencyThreats.push(...dependencyHeuristics(depName, depVersion, packageJsonPath));
    const cleanVersion = depVersion.replace(/^[\^~>=<]+\s*/, '');

    if (options.iocEnabled !== false) {
      budgets.iocQueriesEligible += 1;
      if (budgets.iocQueriesUsed < SCAN_COVERAGE_LIMITS.IOC_QUERIES_PER_SCAN) {
        iocQueries.push(queryIoCProviders(depName, cleanVersion, providerNames, packageJsonPath));
        budgets.iocQueriesUsed += 1;
      }
    }
    if (NLP_CONFIG.ENABLED && nlpQueries.length < 20) {
      nlpQueries.push(nlpThreat(depName, cleanVersion, packageJsonPath, options));
    }
  }

  const extraThreats: Threat[] = [];
  for (const [label, queries] of [
    ['IoC', iocQueries],
    ['NLP', nlpQueries],
  ] as const) {
    if (queries.length === 0) continue;
    try {
      extraThreats.push(...(await Promise.all(queries)).flat());
    } catch (error) {
      if (options.verbose) logger.warn(`${label} query failed: ${(error as Error).message}`);
    }
  }
  result.threats.push(...mergeIoCThreats(dependencyThreats, extraThreats));

  if (options.dependencyConfusionEnabled !== false) {
    try {
      if (options.verbose) logger.info('Analyzing dependency confusion patterns...');
      const packagesToAnalyze = packagesForDependencyConfusion(
        packageDir,
        packageJson,
        dependencies,
        budgets
      );
      if (packagesToAnalyze.length > 0) {
        result.packagesAnalyzed.push(...packagesToAnalyze);
        const depConfusionThreats = await analyzeDependencyConfusion(packagesToAnalyze, {
          emitMlThreats: options.mlThreats === true,
        });
        result.threats.push(...depConfusionThreats);
        for (const t of depConfusionThreats) {
          if (t.filePath && isCodeThreatType(t.type)) {
            const root = findPackageRoot(t.filePath);
            if (root) result.threatPackageRoots.add(path.resolve(root));
          }
        }
        if (options.verbose && depConfusionThreats.length > 0) {
          logger.info(`Found ${depConfusionThreats.length} dependency confusion threat(s)`);
        }
      }
    } catch (error) {
      if (options.verbose) {
        logger.warn(`Dependency confusion analysis failed: ${(error as Error).message}`);
      }
    }
  }

  return result;
}
