/**
 * File discovery and per-file detection for a scan target.
 */

import * as fs from 'fs';
import * as path from 'path';
import type { DirectoryStructure, ProgressCallback, ScanOptions, Threat } from '../types/core';
import { createLogger } from './logger';
import { isNullVoidCode } from './nullvoidDetection';
import { detectMalware } from './detection';
import { detectFileThreats } from './customRuleEngine';

const logger = createLogger('scan');

const SCANABLE_EXTENSIONS = ['.js', '.mjs', '.cjs', '.ts', '.jsx', '.tsx'];

export function isScanableFile(name: string): boolean {
  return SCANABLE_EXTENSIONS.some((ext) => name.endsWith(ext));
}

// Directories never scanned. Build output (dist/, build/, out/) is scanned on
// purpose: published packages often ship only their bundles, and that is
// where the Sept 2025 chalk/debug/ansi-styles drainer lived.
export const SKIP_DIRS = [
  'node_modules',
  '.git',
  '.vscode',
  '.idea',
  '.cursor',
  'coverage',
  '.nyc_output',
  'fixtures',
];

/** Directory names listed in <root>/.nullvoidignore (one per line, `#` comments). */
export function loadNullvoidIgnore(rootPath: string): string[] {
  const ignorePath = path.join(rootPath, '.nullvoidignore');
  if (!fs.existsSync(ignorePath)) return [];
  try {
    const content = fs.readFileSync(ignorePath, 'utf8');
    return content
      .split('\n')
      .map((line) => line.replace(/#.*$/, '').trim())
      .filter((name) => name.length > 0 && !name.startsWith('/'));
  } catch {
    return [];
  }
}

/**
 * Recursively collect all scanable file paths and the directory structure.
 * Recursion is bounded by options.maxDirDepth (default 5), never by the
 * dependency depth.
 */
export function collectScanablePaths(
  dirPath: string,
  options: ScanOptions
): { paths: string[]; directoryStructure: DirectoryStructure } {
  const paths: string[] = [];
  const files: string[] = [];
  const directories: string[] = [];
  const skipDirs = new Set([...SKIP_DIRS, ...(options.ignoreDirs ?? [])]);

  try {
    const entries = fs.readdirSync(dirPath, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.resolve(path.join(dirPath, entry.name));

      if (entry.isDirectory()) {
        if (skipDirs.has(entry.name)) continue;
        directories.push(entry.name);
        const dirDepth = (options.maxDirDepth ?? 5) - 1;
        if (dirDepth > 0) {
          const sub = collectScanablePaths(fullPath, { ...options, maxDirDepth: dirDepth });
          paths.push(...sub.paths);
          files.push(...sub.directoryStructure.files.map((f) => path.join(entry.name, f)));
          directories.push(
            ...sub.directoryStructure.directories.map((d) => path.join(entry.name, d))
          );
        }
      } else if (entry.isFile()) {
        files.push(entry.name);
        if (isScanableFile(entry.name)) paths.push(fullPath);
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
 * Read each file, skip NullVoid's own sources, run the detection pipeline.
 */
export function scanFilePaths(
  filePaths: string[],
  options: ScanOptions,
  progressCallback?: ProgressCallback
): { threats: Threat[]; filesScanned: number } {
  const threats: Threat[] = [];
  let filesScanned = 0;

  for (let i = 0; i < filePaths.length; i++) {
    const fullPath = filePaths[i] as string;
    progressCallback?.({
      current: i + 1,
      total: filePaths.length,
      message: `Scanning ${path.basename(fullPath)}`,
      packageName: fullPath,
    });
    try {
      if (isNullVoidCode(fullPath)) {
        if (options.verbose) logger.info(`Skipping NullVoid file: ${path.basename(fullPath)}`);
        continue;
      }
      const content = fs.readFileSync(fullPath, 'utf8');
      threats.push(...detectFileThreats(content, fullPath, options, detectMalware));
      filesScanned++;
    } catch (error) {
      if (options.verbose) {
        logger.warn(`Failed to scan file ${fullPath}: ${(error as Error).message}`);
      }
    }
  }

  return { threats, filesScanned };
}

/** Totals that count nested path segments, as the legacy result did. */
export function directoryTotals(structure: DirectoryStructure | undefined): {
  totalDirectories: number;
  totalFiles: number;
} {
  const nested = (items: string[]): number =>
    items.length +
    items.reduce((acc, item) => acc + (item.includes('/') ? item.split('/').length - 1 : 0), 0);
  return {
    totalDirectories: structure ? nested(structure.directories) : 0,
    totalFiles: structure ? nested(structure.files) : 0,
  };
}
