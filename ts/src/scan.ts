import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
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
import { isNullVoidCode } from './lib/nullvoidDetection';
import { detectMalware } from './lib/detection';
import { filterThreatsBySeverity } from './lib/detection';
import { queryIoCProviders, mergeIoCThreats } from './lib/iocScanIntegration';
import { analyzeDependencyConfusion } from './lib/dependencyConfusion';
import { getOptimalWorkerCount, getOptimalChunkSize, chunkPackages } from './lib/parallel';
import { SCAN_CONFIG, PARALLEL_CONFIG, NLP_CONFIG } from './lib/config';
import { computeCompositeRisk } from './lib/riskScoring';
import { runNlpAnalysis } from './lib/nlpAnalysis';
import { runMLDetection, buildFeatureVector } from './lib/mlDetection';
import { getGitHistorySync } from './lib/dependencyConfusion';
import { getPackageCreationDate } from './lib/dependencyConfusion';
import { analyzePackageName } from './lib/dependencyConfusion';
import type { IoCProviderName } from './types/ioc-types';

const logger = createLogger('scan');

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

function findPackageRoot(filePath: string): string | null {
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

async function exportThreatsToTraining(
  threats: Threat[],
  outPath: string,
  options: ScanOptions
): Promise<number> {
  const seenPkg = new Set<string>();
  const seenFeatures = new Set<string>();

  if (fs.existsSync(outPath)) {
    try {
      const content = fs.readFileSync(outPath, 'utf8').trim();
      for (const line of content.split('\n')) {
        try {
          const row = JSON.parse(line) as { features?: unknown; label?: number };
          if (row?.features != null && typeof row.label === 'number') {
            seenFeatures.add(JSON.stringify({ f: row.features, l: row.label }));
          }
        } catch {
          /* skip invalid lines */
        }
      }
    } catch {
      /* ignore read errors */
    }
  }

  const lines: string[] = [];

  for (const threat of threats) {
    if (!threat.filePath || !CODE_THREAT_TYPES.has(threat.type)) continue;
    const pkgRoot = findPackageRoot(threat.filePath);
    if (!pkgRoot) continue;
    const pkgRootNorm = path.resolve(pkgRoot);
    if (seenPkg.has(pkgRootNorm)) continue;
    seenPkg.add(pkgRootNorm);

    let packageName: string;
    try {
      const pkg = JSON.parse(fs.readFileSync(path.join(pkgRoot, 'package.json'), 'utf8')) as {
        name?: string;
      };
      packageName = pkg?.name ?? path.basename(pkgRoot);
    } catch {
      continue;
    }

    try {
      let features;
      try {
        const creationDate = await getPackageCreationDate(packageName);
        const gitHistory = getGitHistorySync(pkgRoot);
        const nameAnalysis = analyzePackageName(packageName);

        const result = await runMLDetection({
          creationDate: creationDate ?? null,
          recentCommitCount: gitHistory.recentCommitCount ?? 0,
          scopeType: nameAnalysis.scopeType ?? null,
          suspiciousPatternsCount: nameAnalysis.suspiciousPatterns.length,
          registryName: creationDate ? 'npm' : null,
          firstCommitDate: gitHistory.firstCommitDate ?? null,
          packagePath: pkgRoot,
        });
        features = result.features;
      } catch {
        // Fallback: build minimal features when git/registry unavailable (local malware projects)
        const nameAnalysis = analyzePackageName(packageName);
        features = buildFeatureVector({
          daysDifference: 365,
          recentCommitCount: 0,
          scopeType: nameAnalysis.scopeType ?? null,
          suspiciousPatternsCount: nameAnalysis.suspiciousPatterns.length,
          registryName: null,
        });
      }
      const key = JSON.stringify({ f: features, l: 1 });
      if (seenFeatures.has(key)) continue;
      seenFeatures.add(key);
      lines.push(JSON.stringify({ features, label: 1 }));
    } catch (err) {
      if (options.verbose) {
        logger.warn(`Could not export features for ${packageName}: ${(err as Error).message}`);
      }
    }
  }

  if (lines.length > 0) {
    fs.appendFileSync(outPath, lines.join('\n') + '\n');
  }
  return lines.length;
}

async function exportGoodPackagesToTraining(
  packages: Array<{ name: string; path: string }>,
  outPath: string,
  options: ScanOptions
): Promise<number> {
  const seenPkg = new Set<string>();
  const seenFeatures = new Set<string>();

  if (fs.existsSync(outPath)) {
    try {
      const content = fs.readFileSync(outPath, 'utf8').trim();
      for (const line of content.split('\n')) {
        try {
          const row = JSON.parse(line) as { features?: unknown; label?: number };
          if (row?.features != null && typeof row.label === 'number') {
            seenFeatures.add(JSON.stringify({ f: row.features, l: row.label }));
          }
        } catch {
          /* skip invalid lines */
        }
      }
    } catch {
      /* ignore read errors */
    }
  }

  const lines: string[] = [];

  for (const pkg of packages) {
    const pkgRootNorm = path.resolve(pkg.path);
    if (seenPkg.has(pkgRootNorm)) continue;
    seenPkg.add(pkgRootNorm);

    const packageName = pkg.name;

    try {
      let features;
      try {
        const creationDate = await getPackageCreationDate(packageName);
        const gitHistory = getGitHistorySync(pkg.path);
        const nameAnalysis = analyzePackageName(packageName);

        const result = await runMLDetection({
          creationDate: creationDate ?? null,
          recentCommitCount: gitHistory.recentCommitCount ?? 0,
          scopeType: nameAnalysis.scopeType ?? null,
          suspiciousPatternsCount: nameAnalysis.suspiciousPatterns.length,
          registryName: creationDate ? 'npm' : null,
          firstCommitDate: gitHistory.firstCommitDate ?? null,
          packagePath: pkg.path,
        });
        features = result.features;
      } catch {
        const nameAnalysis = analyzePackageName(packageName);
        features = buildFeatureVector({
          daysDifference: 365,
          recentCommitCount: 0,
          scopeType: nameAnalysis.scopeType ?? null,
          suspiciousPatternsCount: nameAnalysis.suspiciousPatterns.length,
          registryName: null,
        });
      }
      const key = JSON.stringify({ f: features, l: 0 });
      if (seenFeatures.has(key)) continue;
      seenFeatures.add(key);
      lines.push(JSON.stringify({ features, label: 0 }));
    } catch (err) {
      if (options.verbose) {
        logger.warn(`Could not export features for ${packageName}: ${(err as Error).message}`);
      }
    }
  }

  if (lines.length > 0) {
    fs.appendFileSync(outPath, lines.join('\n') + '\n');
  }
  return lines.length;
}

// Performance metrics
const performanceMetrics: PerformanceMetrics = {
  duration: 0,
  memoryUsage: 0,
  cpuUsage: 0,
  filesPerSecond: 0,
  packagesPerSecond: 0,
};

// Suspicious patterns
const SUSPICIOUS_PATTERNS = {
  postinstall: ['rm -rf', 'curl.*|.*sh', 'wget.*|.*sh', 'bash -c.*rm', 'bash -c.*chmod'],
  dependencies: ['http://.*', 'git://.*', 'file://.*'],
  keywords: ['malware', 'virus', 'trojan', 'backdoor'],
};

const SCANABLE_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx'];

function isScanableFile(name: string): boolean {
  return SCANABLE_EXTENSIONS.some((ext) => name.endsWith(ext));
}

const SKIP_DIRS = [
  'node_modules',
  '.git',
  '.vscode',
  '.idea',
  '.cursor',
  'dist',
  'build',
  'coverage',
  '.nyc_output',
  'fixtures',
  'out',
];

/**
 * Recursively collect all scanable file paths and directory structure
 */
function collectScanablePaths(
  dirPath: string,
  options: ScanOptions
): { paths: string[]; directoryStructure: DirectoryStructure } {
  const paths: string[] = [];
  const files: string[] = [];
  const directories: string[] = [];

  try {
    const entries = fs.readdirSync(dirPath, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.resolve(path.join(dirPath, entry.name));

      if (entry.isDirectory()) {
        if (SKIP_DIRS.includes(entry.name)) {
          continue;
        }
        directories.push(entry.name);
        const depth = (options.depth ?? 5) - 1;
        if (depth > 0) {
          const sub = collectScanablePaths(fullPath, { ...options, depth });
          paths.push(...sub.paths);
          files.push(...sub.directoryStructure.files.map((f) => path.join(entry.name, f)));
          directories.push(
            ...sub.directoryStructure.directories.map((d) => path.join(entry.name, d))
          );
        }
      } else if (entry.isFile()) {
        files.push(entry.name);
        if (isScanableFile(entry.name)) {
          paths.push(fullPath);
        }
      }
    }
  } catch (error) {
    if (options.verbose) {
      logger.warn(`Failed to read directory ${dirPath}: ${(error as Error).message}`);
    }
  }

  return {
    paths,
    directoryStructure: {
      path: dirPath,
      files,
      directories,
      totalFiles: files.length,
      totalDirectories: directories.length,
    },
  };
}

/**
 * Recursively find all directories containing package.json (for dependency confusion + ML)
 */
function collectPackageJsonDirs(
  dirPath: string,
  options: ScanOptions,
  maxPackages: number = 50
): string[] {
  const found: string[] = [];
  const depth = options.depth ?? 5;

  function walk(currentPath: string, remainingDepth: number): void {
    if (found.length >= maxPackages || remainingDepth <= 0) return;
    try {
      const pkgPath = path.join(currentPath, 'package.json');
      if (fs.existsSync(pkgPath)) {
        found.push(currentPath);
      }
      const entries = fs.readdirSync(currentPath, { withFileTypes: true });
      for (const entry of entries) {
        if (!entry.isDirectory() || SKIP_DIRS.includes(entry.name)) continue;
        walk(path.join(currentPath, entry.name), remainingDepth - 1);
      }
    } catch {
      /* ignore */
    }
  }

  walk(dirPath, depth);
  return found;
}

/**
 * Process file paths: read content, skip NullVoid files, run detectMalware.
 * Uses parallel chunks when options.parallel and SCAN_CONFIG.enableParallel and path count >= MIN_CHUNK_SIZE.
 */
async function processPaths(
  filePaths: string[],
  options: ScanOptions,
  progressCallback?: ProgressCallback
): Promise<{ threats: Threat[]; filesScanned: number }> {
  const threats: Threat[] = [];
  let filesScanned = 0;

  const useParallel =
    options.parallel !== false &&
    SCAN_CONFIG.enableParallel &&
    filePaths.length >= PARALLEL_CONFIG.MIN_CHUNK_SIZE;

  if (!useParallel) {
    for (let i = 0; i < filePaths.length; i++) {
      const fullPath = filePaths[i] as string;
      if (progressCallback) {
        progressCallback({
          current: i + 1,
          total: filePaths.length,
          message: `Scanning ${path.basename(fullPath)}`,
          packageName: fullPath,
        });
      }
      try {
        const content = fs.readFileSync(fullPath, 'utf8');
        if (isNullVoidCode(fullPath)) {
          if (options.verbose) {
            logger.info(`Skipping NullVoid file: ${path.basename(fullPath)}`);
          }
          continue;
        }
        const fileThreats = detectMalware(content, fullPath);
        threats.push(...fileThreats);
        filesScanned++;
      } catch (error) {
        if (options.verbose) {
          logger.warn(`Failed to scan file ${fullPath}: ${(error as Error).message}`);
        }
      }
    }
    return { threats, filesScanned };
  }

  const workerCount = getOptimalWorkerCount();
  const chunkSize = getOptimalChunkSize(filePaths.length, workerCount);
  const chunks = chunkPackages(filePaths, chunkSize);

  const chunkResults = await Promise.all(
    chunks.map(async (chunk) => {
      const chunkThreats: Threat[] = [];
      let chunkScanned = 0;
      for (const fullPath of chunk) {
        try {
          const content = fs.readFileSync(fullPath, 'utf8');
          if (isNullVoidCode(fullPath)) {
            continue;
          }
          const fileThreats = detectMalware(content, fullPath);
          chunkThreats.push(...fileThreats);
          chunkScanned++;
        } catch (error) {
          if (options.verbose) {
            logger.warn(`Failed to scan file ${fullPath}: ${(error as Error).message}`);
          }
        }
      }
      return { threats: chunkThreats, filesScanned: chunkScanned };
    })
  );

  for (const result of chunkResults) {
    threats.push(...result.threats);
    filesScanned += result.filesScanned;
  }

  if (progressCallback && filePaths.length > 0) {
    progressCallback({
      current: filePaths.length,
      total: filePaths.length,
      message: 'Scan completed',
      packageName: '',
    });
  }

  return { threats, filesScanned };
}

/**
 * Scan a directory for threats (uses parallel file processing when enabled)
 */
async function scanDirectory(
  dirPath: string,
  options: ScanOptions,
  progressCallback?: ProgressCallback
): Promise<{
  threats: Threat[];
  filesScanned: number;
  packagesScanned: number;
  directoryStructure: DirectoryStructure;
}> {
  const { paths, directoryStructure } = collectScanablePaths(dirPath, options);
  const { threats, filesScanned } = await processPaths(paths, options, progressCallback);
  return {
    threats,
    filesScanned,
    packagesScanned: 0,
    directoryStructure,
  };
}

/**
 * Main scan function
 */
export async function scan(
  target: string,
  options: ScanOptions = {},
  progressCallback?: ProgressCallback
): Promise<ScanResult> {
  const startTime = Date.now();

  // Validate inputs
  try {
    validateScanOptions(options);
  } catch (error) {
    logger.error(`Validation error: ${(error as Error).message}`);
    throw error;
  }

  const threats: Threat[] = [];
  const packagesAnalyzedForDepConfusion: Array<{ name: string; path: string }> = [];
  const depConfusionThreatPackageRoots = new Set<string>();
  let packagesScanned = 0;
  let filesScanned = 0;
  let directoryStructure: DirectoryStructure | undefined;
  let performanceData: PerformanceMetrics;

  // Reset performance metrics
  performanceMetrics.duration = 0;
  performanceMetrics.memoryUsage = 0;
  performanceMetrics.cpuUsage = 0;
  performanceMetrics.filesPerSecond = 0;
  performanceMetrics.packagesPerSecond = 0;

  try {
    // If no target specified, scan current directory
    if (!target) {
      target = process.cwd();
    }

    // Check if target is a directory
    if (fs.existsSync(target) && fs.statSync(target).isDirectory()) {
      // Scan directory
      const directoryResult = await scanDirectory(target, options, progressCallback);
      threats.push(...directoryResult.threats);
      filesScanned = directoryResult.filesScanned;
      packagesScanned = directoryResult.packagesScanned;
      directoryStructure = directoryResult.directoryStructure;

      // Find all package.json dirs (root + subdirs) and run dependency analysis + ML on each
      const packageDirs = collectPackageJsonDirs(target, options);
      const MAX_IOC_QUERIES_PER_SCAN = 30; // Cap to avoid rate limits and hangs
      let iocQueriesUsed = 0;

      for (const packageDir of packageDirs) {
        const packageJsonPath = path.join(packageDir, 'package.json');
        if (!fs.existsSync(packageJsonPath)) continue;
        try {
          const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
          const dependencies: Record<string, string> = {
            ...(packageJson.dependencies || {}),
            ...(options.includeDevDependencies !== false ? packageJson.devDependencies || {} : {}),
          };

          if (Object.keys(dependencies).length > 0) {
            packagesScanned += Object.keys(dependencies).length;

            // Check for suspicious dependencies and query IoC providers
            const dependencyThreats: Threat[] = [];
            const iocQueries: Promise<Threat[]>[] = [];
            const nlpQueries: Promise<Threat[]>[] = [];

            for (const [depName, depVersion] of Object.entries(dependencies)) {
              if (typeof depVersion === 'string') {
                // Check for suspicious patterns in dependency names
                if (
                  SUSPICIOUS_PATTERNS.keywords.some((keyword) =>
                    depName.toLowerCase().includes(keyword.toLowerCase())
                  )
                ) {
                  dependencyThreats.push({
                    type: 'SUSPICIOUS_DEPENDENCY',
                    message: `Suspicious dependency name: ${depName}`,
                    filePath: packageJsonPath,
                    filename: 'package.json',
                    severity: 'MEDIUM',
                    details: `Dependency "${depName}" contains suspicious keywords`,
                    confidence: 0.7,
                  });
                }

                // Check for suspicious version patterns
                if (
                  SUSPICIOUS_PATTERNS.dependencies.some((pattern) =>
                    depVersion.match(new RegExp(pattern))
                  )
                ) {
                  dependencyThreats.push({
                    type: 'SUSPICIOUS_DEPENDENCY',
                    message: `Suspicious dependency version: ${depName}@${depVersion}`,
                    filePath: packageJsonPath,
                    filename: 'package.json',
                    severity: 'HIGH',
                    details: `Dependency "${depName}" has suspicious version pattern: ${depVersion}`,
                    confidence: 0.8,
                  });
                }

                // Query IoC providers for vulnerabilities (if enabled, capped to avoid rate limits)
                if (options.iocEnabled !== false && iocQueriesUsed < MAX_IOC_QUERIES_PER_SCAN) {
                  // Extract version from semver range (e.g., "^1.0.0" -> "1.0.0")
                  const cleanVersion = depVersion.replace(/^[\^~>=<]+\s*/, '');

                  // Parse provider names from options
                  let providerNames: IoCProviderName[] | undefined;
                  if (options.iocProviders) {
                    const providerList = options.iocProviders
                      .split(',')
                      .map((p) => p.trim().toLowerCase());
                    providerNames = providerList.filter(
                      (p) => p === 'snyk' || p === 'npm' || p === 'ghsa' || p === 'cve'
                    ) as IoCProviderName[];
                  }

                  iocQueries.push(
                    queryIoCProviders(depName, cleanVersion, providerNames, packageJsonPath)
                  );
                  iocQueriesUsed++;
                }

                // NLP analysis on dependencies (if enabled, limit to avoid rate limits)
                if (NLP_CONFIG.ENABLED && nlpQueries.length < 20) {
                  const cleanVersion = depVersion.replace(/^[\^~>=<]+\s*/, '');
                  nlpQueries.push(
                    runNlpAnalysis(depName, cleanVersion, NLP_CONFIG)
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
                      .catch(() => [])
                  );
                }
              }
            }

            // Wait for IoC and NLP queries, then merge results
            const allExtraThreats: Threat[] = [];
            if (iocQueries.length > 0) {
              try {
                const iocResults = await Promise.all(iocQueries);
                allExtraThreats.push(...iocResults.flat());
              } catch (error) {
                if (options.verbose) {
                  logger.warn(`IoC query failed: ${(error as Error).message}`);
                }
              }
            }
            if (nlpQueries.length > 0) {
              try {
                const nlpResults = await Promise.all(nlpQueries);
                allExtraThreats.push(...nlpResults.flat());
              } catch (error) {
                if (options.verbose) {
                  logger.warn(`NLP query failed: ${(error as Error).message}`);
                }
              }
            }
            const mergedThreats = mergeIoCThreats(dependencyThreats, allExtraThreats);
            threats.push(...mergedThreats);

            // Dependency confusion analysis (root package + node_modules when available)
            if (options.dependencyConfusionEnabled !== false) {
              try {
                if (options.verbose) {
                  logger.info('Analyzing dependency confusion patterns...');
                }
                const packagesToAnalyze: Array<{ name: string; path: string }> = [];
                const rootName = packageJson.name as string | undefined;
                if (rootName) {
                  packagesToAnalyze.push({ name: rootName, path: packageDir });
                }
                const nodeModulesPath = path.join(packageDir, 'node_modules');
                const MAX_DEP_CONFUSION_PACKAGES = 30;
                if (fs.existsSync(nodeModulesPath)) {
                  const deps = {
                    ...((packageJson.dependencies as Record<string, string>) || {}),
                    ...(options.includeDevDependencies !== false
                      ? (packageJson.devDependencies as Record<string, string>) || {}
                      : {}),
                  };
                  for (const depName of Object.keys(deps)) {
                    if (packagesToAnalyze.length >= MAX_DEP_CONFUSION_PACKAGES) break;
                    const depPath = path.join(nodeModulesPath, depName);
                    if (fs.existsSync(depPath)) {
                      packagesToAnalyze.push({ name: depName, path: depPath });
                    }
                  }
                }
                if (packagesToAnalyze.length > 0) {
                  packagesAnalyzedForDepConfusion.push(...packagesToAnalyze);
                  const depConfusionThreats = await analyzeDependencyConfusion(packagesToAnalyze);
                  threats.push(...depConfusionThreats);
                  for (const t of depConfusionThreats) {
                    if (t.filePath && CODE_THREAT_TYPES.has(t.type)) {
                      const root = findPackageRoot(t.filePath);
                      if (root) depConfusionThreatPackageRoots.add(path.resolve(root));
                    }
                  }
                  if (options.verbose && depConfusionThreats.length > 0) {
                    logger.info(
                      `Found ${depConfusionThreats.length} dependency confusion threat(s)`
                    );
                  }
                }
              } catch (error) {
                if (options.verbose) {
                  logger.warn(`Dependency confusion analysis failed: ${(error as Error).message}`);
                }
              }
            }
          }
        } catch (error) {
          if (options.verbose) {
            logger.warn(`Warning: Could not parse package.json: ${(error as Error).message}`);
          }
        }
      }
    } else {
      // Single file scan
      if (fs.existsSync(target)) {
        try {
          const content = fs.readFileSync(target, 'utf8');
          const fileThreats = detectMalware(content, target);
          threats.push(...fileThreats);
          filesScanned = 1;
        } catch (error) {
          if (options.verbose) {
            logger.warn(`Failed to scan file ${target}: ${(error as Error).message}`);
          }
        }
      } else {
        // Assume it's a package name (placeholder for npm package scanning)
        threats.push({
          type: 'PACKAGE_NOT_FOUND',
          message: `Package or file not found: ${target}`,
          filePath: target,
          filename: path.basename(target),
          severity: 'LOW',
          details:
            'This appears to be a package name, but npm package scanning is not yet implemented in the TypeScript version.',
          confidence: 0.5,
        });
      }
    }
  } catch (error) {
    logger.error(`Scan error: ${(error as Error).message}`);
    threats.push({
      type: 'SCAN_ERROR',
      message: `Scan failed: ${(error as Error).message}`,
      filePath: target,
      filename: path.basename(target),
      severity: 'MEDIUM',
      details: (error as Error).stack || '',
      confidence: 0.9,
    });
  }

  // Calculate performance metrics
  const duration = Date.now() - startTime;
  const memoryUsage = process.memoryUsage().heapUsed / 1024 / 1024; // MB
  const cpuUsage = os.loadavg()[0] || 0;

  performanceData = {
    duration,
    memoryUsage,
    cpuUsage,
    filesPerSecond:
      filesScanned > 0 && duration > 0 ? Math.round(filesScanned / (duration / 1000)) : 0,
    packagesPerSecond:
      packagesScanned > 0 && duration > 0 ? Math.round(packagesScanned / (duration / 1000)) : 0,
  };

  // Filter threats based on options
  const filteredThreats = filterThreatsBySeverity(threats, options.all || false);

  // Compute composite risk assessment
  const riskAssessment = computeCompositeRisk(filteredThreats);

  // Export training data for packages with threats (use unfiltered threats)
  if (options.exportTrainingData && threats.length > 0) {
    try {
      const outPath = path.resolve(options.exportTrainingData);
      const exported = await exportThreatsToTraining(threats, outPath, options);
      if (exported > 0) {
        logger.info(`Exported ${exported} threat package(s) to ${outPath} (label 1)`);
      }
    } catch (err) {
      if (options.verbose) {
        logger.warn(`Export training failed: ${(err as Error).message}`);
      }
    }
  }

  // Export training data for packages with no dependency confusion threats (label 0)
  if (options.exportTrainingGood && packagesAnalyzedForDepConfusion.length > 0) {
    try {
      const goodPackages = packagesAnalyzedForDepConfusion.filter(
        (p) => !depConfusionThreatPackageRoots.has(path.resolve(p.path))
      );
      if (goodPackages.length > 0) {
        const outPath = path.resolve(options.exportTrainingGood);
        const exported = await exportGoodPackagesToTraining(goodPackages, outPath, options);
        if (exported > 0) {
          logger.info(`Exported ${exported} clean package(s) to ${outPath} (label 0)`);
        }
      }
    } catch (err) {
      if (options.verbose) {
        logger.warn(`Export training good failed: ${(err as Error).message}`);
      }
    }
  }

  // Calculate directory structure totals
  const totalDirectories = directoryStructure
    ? directoryStructure.directories.length +
      directoryStructure.directories.reduce(
        (acc, dir) => acc + (dir.includes('/') ? dir.split('/').length - 1 : 0),
        0
      )
    : 0;
  const totalFiles = directoryStructure
    ? directoryStructure.files.length +
      directoryStructure.files.reduce(
        (acc, file) => acc + (file.includes('/') ? file.split('/').length - 1 : 0),
        0
      )
    : 0;

  return {
    threats: filteredThreats,
    metrics: performanceData,
    summary: {
      totalFiles: filesScanned,
      totalPackages: packagesScanned,
      threatsFound: filteredThreats.length,
      scanDuration: duration,
    },
    packagesScanned,
    filesScanned,
    performance: performanceData,
    metadata: {
      target,
      scanTime: new Date().toISOString(),
      options,
    },
    directoryStructure: directoryStructure
      ? {
          ...directoryStructure,
          totalDirectories,
          totalFiles,
        }
      : { path: target, files: [], directories: [], totalDirectories: 0, totalFiles: 0 },
    dependencyTree: {
      totalPackages: packagesScanned,
      maxDepth: 5, // Placeholder
      packagesWithThreats: filteredThreats.length > 0 ? 1 : 0,
      deepDependencies: 0, // Placeholder
    },
    riskAssessment,
  };
}
