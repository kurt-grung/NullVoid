import * as fs from 'fs';
import * as path from 'path';
import type { ScanOptions } from '../types/core';
import { DEPENDENCY_SOURCE_SCAN_CONFIG } from './config';

const SCANABLE_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx'];

const SKIP_INSIDE_PACKAGE = new Set([
  'node_modules',
  '.git',
  'coverage',
  '.nyc_output',
  'test',
  'tests',
  '__tests__',
]);

export interface DependencySourceScanStats {
  packagesVisited: number;
  filesCollected: number;
  truncatedByFileBudget: boolean;
  truncatedByPackageBudget: boolean;
}

function isScanableFile(name: string): boolean {
  return SCANABLE_EXTENSIONS.some((ext) => name.endsWith(ext));
}

function clampInt(value: number | undefined, fallback: number, min: number, max: number): number {
  if (value === undefined || !Number.isFinite(value)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(value)));
}

function listPackageRoots(nodeModulesDir: string): string[] {
  const roots: string[] = [];
  if (!fs.existsSync(nodeModulesDir)) return roots;

  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(nodeModulesDir, { withFileTypes: true });
  } catch {
    return roots;
  }

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    if (entry.name === '.bin' || entry.name.startsWith('.')) continue;

    if (entry.name.startsWith('@')) {
      const scopeDir = path.join(nodeModulesDir, entry.name);
      let scoped: fs.Dirent[];
      try {
        scoped = fs.readdirSync(scopeDir, { withFileTypes: true });
      } catch {
        continue;
      }
      for (const scopedEntry of scoped) {
        if (!scopedEntry.isDirectory()) continue;
        const pkgRoot = path.join(scopeDir, scopedEntry.name);
        if (fs.existsSync(path.join(pkgRoot, 'package.json'))) {
          roots.push(pkgRoot);
        }
      }
      continue;
    }

    const pkgRoot = path.join(nodeModulesDir, entry.name);
    if (fs.existsSync(path.join(pkgRoot, 'package.json'))) {
      roots.push(pkgRoot);
    }
  }

  return roots;
}

export function discoverInstalledPackageRoots(projectRoot: string): string[] {
  const resolvedRoot = path.resolve(projectRoot);
  const seen = new Set<string>();
  const queue: string[] = [];

  const rootNodeModules = path.join(resolvedRoot, 'node_modules');
  if (fs.existsSync(rootNodeModules)) {
    queue.push(rootNodeModules);
  }

  while (queue.length > 0) {
    const nodeModulesDir = queue.pop() as string;
    for (const pkgRoot of listPackageRoots(nodeModulesDir)) {
      const normalized = path.resolve(pkgRoot);
      if (seen.has(normalized)) continue;
      seen.add(normalized);

      const nested = path.join(normalized, 'node_modules');
      if (fs.existsSync(nested)) {
        queue.push(nested);
      }
    }
  }

  return [...seen];
}

function collectFilesInPackage(
  packageRoot: string,
  fileDepth: number,
  paths: string[],
  maxFiles: number
): boolean {
  if (paths.length >= maxFiles) return true;

  const stack: Array<{ dir: string; depth: number }> = [{ dir: packageRoot, depth: fileDepth }];

  while (stack.length > 0) {
    const frame = stack.pop() as { dir: string; depth: number };
    if (paths.length >= maxFiles) return true;

    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(frame.dir, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      if (paths.length >= maxFiles) return true;
      const fullPath = path.join(frame.dir, entry.name);

      if (entry.isDirectory()) {
        if (frame.depth <= 0 || SKIP_INSIDE_PACKAGE.has(entry.name)) continue;
        stack.push({ dir: fullPath, depth: frame.depth - 1 });
        continue;
      }

      if (entry.isFile() && isScanableFile(entry.name)) {
        paths.push(path.resolve(fullPath));
      }
    }
  }

  return false;
}

export function collectInstalledDependencySourcePaths(
  projectRoot: string,
  options: ScanOptions
): { paths: string[]; stats: DependencySourceScanStats } {
  const enabled = options.scanDependencySource !== false;
  if (!enabled) {
    return {
      paths: [],
      stats: {
        packagesVisited: 0,
        filesCollected: 0,
        truncatedByFileBudget: false,
        truncatedByPackageBudget: false,
      },
    };
  }

  const maxPackages = clampInt(
    options.maxDependencySourcePackages,
    DEPENDENCY_SOURCE_SCAN_CONFIG.MAX_PACKAGES,
    1,
    500
  );
  const maxFiles = clampInt(
    options.maxDependencySourceFiles,
    DEPENDENCY_SOURCE_SCAN_CONFIG.MAX_FILES,
    1,
    10_000
  );
  const fileDepth = clampInt(
    options.dependencySourceFileDepth,
    DEPENDENCY_SOURCE_SCAN_CONFIG.FILE_DEPTH,
    1,
    20
  );

  const packageRoots = discoverInstalledPackageRoots(projectRoot);
  const paths: string[] = [];
  let packagesVisited = 0;
  let truncatedByFileBudget = false;
  let truncatedByPackageBudget = packageRoots.length > maxPackages;

  for (const pkgRoot of packageRoots) {
    if (packagesVisited >= maxPackages) break;
    packagesVisited += 1;
    const hitFileCap = collectFilesInPackage(pkgRoot, fileDepth, paths, maxFiles);
    if (hitFileCap) {
      truncatedByFileBudget = true;
      break;
    }
  }

  const unique = [...new Set(paths)];

  return {
    paths: unique,
    stats: {
      packagesVisited,
      filesCollected: unique.length,
      truncatedByFileBudget,
      truncatedByPackageBudget,
    },
  };
}
