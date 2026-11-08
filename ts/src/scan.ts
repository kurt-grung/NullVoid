import * as fs from 'fs';
import * as path from 'path';
import {
  ScanOptions,
  ScanResult,
  Threat,
  ProgressCallback,
  DirectoryStructure,
  PerformanceMetrics,
} from './types/core';
import { createLogger } from './lib/logger';
import { validateScanOptions } from './lib/validation';
import { filterThreatsBySeverity } from './lib/detection';
import { collectProjectPackageRoots } from './lib/projectPackageRoots';
import {
  buildScanTruncationReport,
  truncationCap,
  type ScanTruncationReport,
} from './lib/scanTruncation';
import type { DependencySourceScanStats } from './lib/dependencySourceScan';
import type { LifecycleScriptScanStats } from './lib/lifecycleScriptAnalysis';
import { SCAN_COVERAGE_LIMITS } from './lib/config';
import { computeCompositeRisk } from './lib/riskScoring';
import { isNpmPackageSpec, parsePackageSpec, downloadPackageToTemp } from './lib/remotePackageScan';
import { buildSupplyChainGraph, countPackagesWithThreats } from './lib/supplyChainGraph';
import { buildDependencyTree, type DependencyTreeStats } from './lib/dependencyTree';
import { collectInstalledDependencySourcePaths } from './lib/dependencySourceScan';
import { collectLifecycleScriptThreatsForProject } from './lib/lifecycleScriptAnalysis';
import {
  collectScanablePaths,
  directoryTotals,
  loadNullvoidIgnore,
  scanFilePaths,
} from './lib/scanFiles';
import {
  analyzeManifest,
  createScanBudgets,
  type PackageRef,
  type ScanBudgets,
} from './lib/manifestAnalysis';
import { exportPackagesToTraining, packagesWithThreats } from './lib/trainingExport';

const logger = createLogger('scan');

type CpuUsage = ReturnType<typeof process.cpuUsage>;

/**
 * Everything a target scan produces before enrichment. One instance per
 * scan() call; the target-specific functions fill it in.
 */
interface ScanState {
  target: string;
  options: ScanOptions;
  threats: Threat[];
  filesScanned: number;
  packagesScanned: number;
  directoryStructure?: DirectoryStructure;
  /** Root used for the dependency tree / supply-chain graph */
  graphRoot: string | null;
  budgets: ScanBudgets;
  projectPackageRoots?: ReturnType<typeof collectProjectPackageRoots>;
  dependencySourceStats?: DependencySourceScanStats;
  lifecycleScriptStats?: LifecycleScriptScanStats;
  /** Packages that went through dependency-confusion analysis (training export) */
  packagesAnalyzedForDepConfusion: PackageRef[];
  /** Package roots with a code-level dependency-confusion threat (training export) */
  depConfusionThreatPackageRoots: Set<string>;
}

function createScanState(target: string, options: ScanOptions): ScanState {
  return {
    target,
    options,
    threats: [],
    filesScanned: 0,
    packagesScanned: 0,
    graphRoot: null,
    budgets: createScanBudgets(),
    packagesAnalyzedForDepConfusion: [],
    depConfusionThreatPackageRoots: new Set(),
  };
}

// ---------------------------------------------------------------------------
// Targets
// ---------------------------------------------------------------------------

/**
 * Directory target: project files, installed dependency source, lifecycle
 * scripts and one manifest analysis per package.json under the root.
 */
async function scanDirectoryTarget(
  state: ScanState,
  dirPath: string,
  progressCallback?: ProgressCallback
): Promise<void> {
  const rootPath = path.resolve(dirPath);
  const ignoreDirs = loadNullvoidIgnore(rootPath);
  const options = ignoreDirs.length > 0 ? { ...state.options, ignoreDirs } : state.options;
  state.graphRoot = rootPath;

  const { paths, directoryStructure } = collectScanablePaths(dirPath, options);
  state.directoryStructure = directoryStructure;
  const project = scanFilePaths(paths, options, progressCallback);
  state.threats.push(...project.threats);
  state.filesScanned += project.filesScanned;

  const dependencySource = collectInstalledDependencySourcePaths(rootPath, options);
  state.dependencySourceStats = dependencySource.stats;
  if (dependencySource.paths.length > 0) {
    const depScan = scanFilePaths(dependencySource.paths, options, progressCallback);
    state.threats.push(...depScan.threats);
    state.filesScanned += depScan.filesScanned;
    state.packagesScanned += dependencySource.stats.packagesVisited;
  }

  state.projectPackageRoots = collectProjectPackageRoots(dirPath, options);
  const packageDirs = state.projectPackageRoots.dirs;

  const lifecycleScan = collectLifecycleScriptThreatsForProject(rootPath, options, packageDirs);
  state.threats.push(...lifecycleScan.threats);
  state.lifecycleScriptStats = lifecycleScan.stats;

  for (const packageDir of packageDirs) {
    const manifest = await analyzeManifest(packageDir, state.options, state.budgets);
    if (!manifest) continue;
    state.packagesScanned += manifest.dependencyCount;
    state.threats.push(...manifest.threats);
    state.packagesAnalyzedForDepConfusion.push(...manifest.packagesAnalyzed);
    for (const root of manifest.threatPackageRoots) state.depConfusionThreatPackageRoots.add(root);
  }
}

/** Single file target. */
function scanFileTarget(state: ScanState, filePath: string): void {
  const { threats, filesScanned } = scanFilePaths([filePath], state.options);
  state.threats.push(...threats);
  state.filesScanned += filesScanned;
}

/** `name` / `name@version`: download the tarball and scan it as a directory. */
async function scanRemoteTarget(
  state: ScanState,
  spec: { name: string; version: string },
  progressCallback?: ProgressCallback
): Promise<void> {
  const resolved = await downloadPackageToTemp(spec.name, spec.version);
  if (!resolved) {
    state.threats.push({
      type: 'PACKAGE_NOT_FOUND',
      message: `Could not download package: ${state.target}`,
      filePath: state.target,
      filename: path.basename(state.target),
      severity: 'MEDIUM',
      details: `Package ${spec.name}@${spec.version} was not found on the npm registry.`,
      confidence: 0.9,
    });
    return;
  }
  try {
    if (state.options.verbose) {
      logger.info(`Scanning remote package ${resolved.packageName}@${resolved.version}`);
    }
    const { paths, directoryStructure } = collectScanablePaths(resolved.extractDir, state.options);
    const files = scanFilePaths(paths, state.options, progressCallback);
    state.threats.push(...files.threats);
    state.filesScanned += files.filesScanned;
    state.packagesScanned = 1;
    state.directoryStructure = directoryStructure;
    state.graphRoot = resolved.extractDir;
  } finally {
    resolved.cleanup();
  }
}

function notFoundThreat(target: string): Threat {
  return {
    type: 'PACKAGE_NOT_FOUND',
    message: `Package or file not found: ${target}`,
    filePath: target,
    filename: path.basename(target),
    severity: 'LOW',
    details:
      'Path does not exist and target is not a valid npm package spec (name or name@version).',
    confidence: 0.5,
  };
}

async function scanTarget(state: ScanState, progressCallback?: ProgressCallback): Promise<void> {
  const { target } = state;
  if (fs.existsSync(target)) {
    if (fs.statSync(target).isDirectory()) {
      await scanDirectoryTarget(state, target, progressCallback);
    } else {
      scanFileTarget(state, target);
    }
    return;
  }
  if (isNpmPackageSpec(target)) {
    const spec = parsePackageSpec(target);
    if (spec) {
      await scanRemoteTarget(state, spec, progressCallback);
      return;
    }
  }
  state.threats.push(notFoundThreat(target));
}

// ---------------------------------------------------------------------------
// Enrichment
// ---------------------------------------------------------------------------

function assembleScanTruncations(state: ScanState): ScanTruncationReport | undefined {
  const { options, projectPackageRoots, budgets, dependencySourceStats, lifecycleScriptStats } =
    state;
  return buildScanTruncationReport([
    projectPackageRoots
      ? truncationCap(
          'projectPackageRoots',
          projectPackageRoots.limit,
          projectPackageRoots.dirs.length,
          projectPackageRoots.discovered
        )
      : undefined,
    options.iocEnabled !== false
      ? truncationCap(
          'iocQueriesPerScan',
          SCAN_COVERAGE_LIMITS.IOC_QUERIES_PER_SCAN,
          budgets.iocQueriesUsed,
          budgets.iocQueriesEligible
        )
      : undefined,
    options.dependencyConfusionEnabled !== false
      ? truncationCap(
          'dependencyConfusionPackages',
          SCAN_COVERAGE_LIMITS.DEPENDENCY_CONFUSION_PACKAGES,
          budgets.depConfusionProcessed,
          budgets.depConfusionEligible
        )
      : undefined,
    dependencySourceStats?.truncatedByPackageBudget
      ? truncationCap(
          'dependencySourcePackages',
          dependencySourceStats.packageLimit,
          dependencySourceStats.packagesVisited,
          dependencySourceStats.packagesEligible
        )
      : undefined,
    dependencySourceStats?.truncatedByFileBudget && dependencySourceStats.filesSkipped > 0
      ? truncationCap(
          'dependencySourceFiles',
          dependencySourceStats.fileLimit,
          dependencySourceStats.filesCollected,
          dependencySourceStats.filesCollected + dependencySourceStats.filesSkipped
        )
      : undefined,
    lifecycleScriptStats?.truncatedByPackageBudget
      ? truncationCap(
          'lifecycleScriptPackages',
          lifecycleScriptStats.packageLimit,
          lifecycleScriptStats.packageJsonFilesAnalyzed,
          lifecycleScriptStats.packageJsonFilesEligible
        )
      : undefined,
  ]);
}

/**
 * CPU time this process spent during the scan as a percentage of wall time
 * (100 = one core busy throughout).
 */
function cpuPercent(start: CpuUsage, durationMs: number): number {
  if (durationMs <= 0) return 0;
  const delta = process.cpuUsage(start);
  return Math.round(((delta.user + delta.system) / 1000 / durationMs) * 100);
}

function performanceMetrics(
  state: ScanState,
  startTime: number,
  cpuStart: CpuUsage
): PerformanceMetrics {
  const duration = Date.now() - startTime;
  const perSecond = (n: number): number =>
    n > 0 && duration > 0 ? Math.round(n / (duration / 1000)) : 0;
  return {
    duration,
    memoryUsage: process.memoryUsage().heapUsed / 1024 / 1024,
    cpuUsage: cpuPercent(cpuStart, duration),
    filesPerSecond: perSecond(state.filesScanned),
    packagesPerSecond: perSecond(state.packagesScanned),
  };
}

async function exportTrainingRows(state: ScanState): Promise<void> {
  const { options, threats } = state;
  if (options.exportTrainingData && threats.length > 0) {
    try {
      const outPath = path.resolve(options.exportTrainingData);
      const exported = await exportPackagesToTraining(
        packagesWithThreats(threats),
        1,
        outPath,
        options
      );
      if (exported > 0) {
        logger.info(`Exported ${exported} threat package(s) to ${outPath} (label 1)`);
      }
    } catch (err) {
      if (options.verbose) logger.warn(`Export training failed: ${(err as Error).message}`);
    }
  }
  if (options.exportTrainingGood && state.packagesAnalyzedForDepConfusion.length > 0) {
    try {
      const clean = state.packagesAnalyzedForDepConfusion.filter(
        (p) => !state.depConfusionThreatPackageRoots.has(path.resolve(p.path))
      );
      if (clean.length > 0) {
        const outPath = path.resolve(options.exportTrainingGood);
        const exported = await exportPackagesToTraining(clean, 0, outPath, options);
        if (exported > 0) {
          logger.info(`Exported ${exported} clean package(s) to ${outPath} (label 0)`);
        }
      }
    } catch (err) {
      if (options.verbose) logger.warn(`Export training good failed: ${(err as Error).message}`);
    }
  }
}

/** Dependency tree + supply-chain graph for the scanned root (best effort). */
function dependencyEnrichment(
  state: ScanState,
  filteredThreats: Threat[]
): {
  supplyChainGraph?: ReturnType<typeof buildSupplyChainGraph>;
  dependencyStats?: DependencyTreeStats;
} {
  if (!state.graphRoot) return {};
  try {
    const { tree, stats } = buildDependencyTree(state.graphRoot, {
      maxDepth: state.options.depth,
      includeDevDependencies: state.options.includeDevDependencies,
    });
    return {
      dependencyStats: stats,
      supplyChainGraph: buildSupplyChainGraph(tree, filteredThreats),
    };
  } catch {
    return {};
  }
}

async function enrichResult(
  state: ScanState,
  startTime: number,
  cpuStart: CpuUsage
): Promise<ScanResult> {
  const { options, target } = state;
  const metrics = performanceMetrics(state, startTime, cpuStart);
  const filteredThreats = filterThreatsBySeverity(state.threats, options.all || false);
  const riskAssessment = computeCompositeRisk(filteredThreats);

  await exportTrainingRows(state);

  const scanTruncations = assembleScanTruncations(state);
  const { supplyChainGraph, dependencyStats } = dependencyEnrichment(state, filteredThreats);
  const totals = directoryTotals(state.directoryStructure);

  return {
    threats: filteredThreats,
    metrics,
    summary: {
      totalFiles: state.filesScanned,
      totalPackages: state.packagesScanned,
      threatsFound: filteredThreats.length,
      scanDuration: metrics.duration,
    },
    packagesScanned: state.packagesScanned,
    filesScanned: state.filesScanned,
    performance: metrics,
    metadata: {
      target,
      scanTime: new Date().toISOString(),
      options,
      ...(state.dependencySourceStats ? { dependencySourceScan: state.dependencySourceStats } : {}),
      ...(state.lifecycleScriptStats
        ? { lifecycleScriptAnalysis: state.lifecycleScriptStats }
        : {}),
      ...(supplyChainGraph ? { supplyChainGraph } : {}),
      ...(scanTruncations ? { scanTruncations } : {}),
    },
    ...(scanTruncations ? { scanTruncations } : {}),
    directoryStructure: state.directoryStructure
      ? { ...state.directoryStructure, ...totals }
      : { path: target, files: [], directories: [], totalDirectories: 0, totalFiles: 0 },
    dependencyTree: {
      totalPackages: dependencyStats?.totalPackages ?? state.packagesScanned,
      maxDepth: dependencyStats?.maxDepth ?? 0,
      packagesWithThreats:
        supplyChainGraph?.packagesWithThreats ?? countPackagesWithThreats(filteredThreats),
      deepDependencies: dependencyStats?.deepDependencies ?? 0,
    },
    riskAssessment,
  };
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/**
 * Scan a directory, a file, or an npm package spec (`name`, `name@version`).
 */
export async function scan(
  target: string,
  options: ScanOptions = {},
  progressCallback?: ProgressCallback
): Promise<ScanResult> {
  const startTime = Date.now();
  const cpuStart = process.cpuUsage();

  try {
    validateScanOptions(options);
  } catch (error) {
    logger.error(`Validation error: ${(error as Error).message}`);
    throw error;
  }

  const state = createScanState(target || process.cwd(), options);
  try {
    await scanTarget(state, progressCallback);
  } catch (error) {
    logger.error(`Scan error: ${(error as Error).message}`);
    state.threats.push({
      type: 'SCAN_ERROR',
      message: `Scan failed: ${(error as Error).message}`,
      filePath: state.target,
      filename: path.basename(state.target),
      severity: 'MEDIUM',
      details: (error as Error).stack || '',
      confidence: 0.9,
    });
  }

  return enrichResult(state, startTime, cpuStart);
}
