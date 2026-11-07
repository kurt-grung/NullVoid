import * as fs from 'fs';
import * as path from 'path';
import type { ScanOptions } from '../types/core';
import { SCAN_COVERAGE_LIMITS } from './config';

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

export interface ProjectPackageRootsResult {
  dirs: string[];
  discovered: number;
  limit: number;
}

export function collectProjectPackageRoots(
  dirPath: string,
  options: ScanOptions,
  maxPackages: number = SCAN_COVERAGE_LIMITS.PROJECT_PACKAGE_ROOTS
): ProjectPackageRootsResult {
  const found: string[] = [];
  let discovered = 0;
  // Directory recursion is bounded by maxDirDepth; `depth` is the dependency-tree depth.
  const depth = options.maxDirDepth ?? 5;

  function walk(currentPath: string, remainingDepth: number): void {
    if (remainingDepth <= 0) return;
    try {
      const pkgPath = path.join(currentPath, 'package.json');
      if (fs.existsSync(pkgPath)) {
        discovered += 1;
        if (found.length < maxPackages) {
          found.push(currentPath);
        }
      }
      const entries = fs.readdirSync(currentPath, { withFileTypes: true });
      const skipDirs = [...SKIP_DIRS, ...(options.ignoreDirs ?? [])];
      for (const entry of entries) {
        if (!entry.isDirectory() || skipDirs.includes(entry.name)) continue;
        walk(path.join(currentPath, entry.name), remainingDepth - 1);
      }
    } catch {
      /* ignore */
    }
  }

  walk(dirPath, depth);
  return { dirs: found, discovered, limit: maxPackages };
}
