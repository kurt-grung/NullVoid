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
import type { IoCProviderName } from './types/ioc-types';

const logger = createLogger('scan');

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

/**
 * Scan a directory for threats
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
  const threats: Threat[] = [];
  let filesScanned = 0;
  let packagesScanned = 0;
  const files: string[] = [];
  const directories: string[] = [];

  try {
    const entries = fs.readdirSync(dirPath, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.resolve(path.join(dirPath, entry.name));

      // Skip common directories that shouldn't be scanned
      if (entry.isDirectory()) {
        const skipDirs = [
          'node_modules',
          '.git',
          '.vscode',
          '.idea',
          'dist',
          'build',
          'coverage',
          '.nyc_output',
        ];
        if (skipDirs.includes(entry.name)) {
          continue;
        }

        directories.push(entry.name);

        // Recursively scan subdirectories (with depth limit)
        const depth = (options.depth || 5) - 1;
        if (depth > 0) {
          const subResult = await scanDirectory(fullPath, { ...options, depth }, progressCallback);
          threats.push(...subResult.threats);
          filesScanned += subResult.filesScanned;
          packagesScanned += subResult.packagesScanned;
          // Merge subdirectory files and directories
          files.push(...subResult.directoryStructure.files.map((f) => path.join(entry.name, f)));
          directories.push(
            ...subResult.directoryStructure.directories.map((d) => path.join(entry.name, d))
          );
        }
      } else if (entry.isFile()) {
        files.push(entry.name);

        // Check if it's a JavaScript file
        if (
          entry.name.endsWith('.js') ||
          entry.name.endsWith('.ts') ||
          entry.name.endsWith('.jsx') ||
          entry.name.endsWith('.tsx')
        ) {
          // Call progress callback for all files (including skipped ones)
          if (progressCallback) {
            progressCallback({
              current: filesScanned + 1,
              total: 0, // We don't know total in advance
              message: `Scanning ${entry.name}`,
              packageName: fullPath,
            });
          }

          try {
            const content = fs.readFileSync(fullPath, 'utf8');

            // Skip NullVoid's own files
            if (isNullVoidCode(fullPath)) {
              if (options.verbose) {
                logger.info(`Skipping NullVoid file: ${entry.name}`);
              }
              continue;
            }

            // Detect threats in the file
            const fileThreats = detectMalware(content, fullPath);
            threats.push(...fileThreats);

            filesScanned++;
          } catch (error) {
            if (options.verbose) {
              logger.warn(`Failed to scan file ${fullPath}: ${(error as Error).message}`);
            }
          }
        }
      }
    }
  } catch (error) {
    if (options.verbose) {
      logger.warn(`Failed to scan directory ${dirPath}: ${(error as Error).message}`);
    }
  }

  return {
    threats,
    filesScanned,
    packagesScanned,
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

      // Also scan package.json if it exists
      const packageJsonPath = path.join(target, 'package.json');
      if (fs.existsSync(packageJsonPath)) {
        try {
          const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
          const dependencies = {
            ...packageJson.dependencies,
            ...packageJson.devDependencies,
          };

          if (Object.keys(dependencies).length > 0) {
            packagesScanned += Object.keys(dependencies).length;

            // Check for suspicious dependencies and query IoC providers
            const dependencyThreats: Threat[] = [];
            const iocQueries: Promise<Threat[]>[] = [];

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

                // Query IoC providers for vulnerabilities (if enabled)
                if (options.iocEnabled !== false) {
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
                }
              }
            }

            // Wait for IoC queries and merge results BEFORE adding to threats
            if (iocQueries.length > 0) {
              try {
                const iocResults = await Promise.all(iocQueries);
                const allIocThreats = iocResults.flat();
                // Merge IoC threats with dependency threats, then add to main threats list
                const mergedThreats = mergeIoCThreats(dependencyThreats, allIocThreats);
                threats.push(...mergedThreats);
              } catch (error) {
                if (options.verbose) {
                  logger.warn(`IoC query failed: ${(error as Error).message}`);
                }
                // Still add dependency threats even if IoC fails
                threats.push(...dependencyThreats);
              }
            } else {
              // No IoC queries, just add dependency threats
              threats.push(...dependencyThreats);
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
  };
}
