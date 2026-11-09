/**
 * `--export-training` / `--export-training-good`: append ML feature rows for
 * the packages a scan touched.
 *
 * The label is the scanner's own verdict, not ground truth, so every row is
 * tagged `source: scanner-threats` / `scanner-clean`; ml-model/train.py drops
 * such rows unless --allow-scanner-labels is passed (see ml-model/README.md).
 */

import * as fs from 'fs';
import * as path from 'path';
import type { ScanOptions, Threat } from '../types/core';
import { createLogger } from './logger';
import { runMLDetection, buildFeatureVector } from './mlDetection';
import {
  analyzePackageName,
  getGitHistorySync,
  getPackagePublishInfo,
} from './dependencyConfusion';
import { publishHistoryFeatures } from './publishHistory';
import { findPackageRoot, isCodeThreatType, type PackageRef } from './manifestAnalysis';

const logger = createLogger('scan');

export type TrainingLabel = 0 | 1;

/** Package roots that produced a code-level threat, named from their package.json. */
export function packagesWithThreats(threats: Threat[]): PackageRef[] {
  const seen = new Set<string>();
  const out: PackageRef[] = [];
  for (const threat of threats) {
    if (!threat.filePath || !isCodeThreatType(threat.type)) continue;
    const pkgRoot = findPackageRoot(threat.filePath);
    if (!pkgRoot) continue;
    const norm = path.resolve(pkgRoot);
    if (seen.has(norm)) continue;
    seen.add(norm);
    try {
      const pkg = JSON.parse(fs.readFileSync(path.join(pkgRoot, 'package.json'), 'utf8')) as {
        name?: string;
      };
      out.push({ name: pkg?.name ?? path.basename(pkgRoot), path: pkgRoot });
    } catch {
      /* unreadable package.json: skip */
    }
  }
  return out;
}

function existingRowKeys(outPath: string): Set<string> {
  const keys = new Set<string>();
  if (!fs.existsSync(outPath)) return keys;
  try {
    for (const line of fs.readFileSync(outPath, 'utf8').trim().split('\n')) {
      try {
        const row = JSON.parse(line) as { features?: unknown; label?: number };
        if (row?.features != null && typeof row.label === 'number') {
          keys.add(JSON.stringify({ f: row.features, l: row.label }));
        }
      } catch {
        /* skip invalid lines */
      }
    }
  } catch {
    /* ignore read errors */
  }
  return keys;
}

async function featuresForPackage(pkg: PackageRef): Promise<Record<string, unknown>> {
  const nameAnalysis = analyzePackageName(pkg.name);
  try {
    const publishInfo = await getPackagePublishInfo(pkg.name);
    const creationDate = publishInfo?.created ?? null;
    const gitHistory = getGitHistorySync(pkg.path);
    const result = await runMLDetection({
      creationDate,
      recentCommitCount: gitHistory.recentCommitCount ?? 0,
      scopeType: nameAnalysis.scopeType ?? null,
      suspiciousPatternsCount: nameAnalysis.suspiciousPatterns.length,
      registryName: creationDate ? 'npm' : null,
      firstCommitDate: gitHistory.firstCommitDate ?? null,
      packagePath: pkg.path,
      publishHistory: publishInfo ? publishHistoryFeatures(pkg.name, publishInfo.time) : null,
    });
    return result.features as unknown as Record<string, unknown>;
  } catch {
    // Minimal features when git/registry are unavailable (local malware projects).
    return buildFeatureVector({
      daysDifference: 365,
      recentCommitCount: 0,
      scopeType: nameAnalysis.scopeType ?? null,
      suspiciousPatternsCount: nameAnalysis.suspiciousPatterns.length,
      registryName: null,
    }) as unknown as Record<string, unknown>;
  }
}

/**
 * Append one feature row per package to a JSONL file, skipping rows whose
 * features are already present. Returns the number of rows written.
 */
export async function exportPackagesToTraining(
  packages: PackageRef[],
  label: TrainingLabel,
  outPath: string,
  options: ScanOptions
): Promise<number> {
  const seenFeatures = existingRowKeys(outPath);
  const seenPkg = new Set<string>();
  const lines: string[] = [];
  const source = label === 1 ? 'scanner-threats' : 'scanner-clean';

  for (const pkg of packages) {
    const norm = path.resolve(pkg.path);
    if (seenPkg.has(norm)) continue;
    seenPkg.add(norm);
    try {
      const features = await featuresForPackage(pkg);
      const key = JSON.stringify({ f: features, l: label });
      if (seenFeatures.has(key)) continue;
      seenFeatures.add(key);
      lines.push(JSON.stringify({ features, label, name: pkg.name, source }));
    } catch (err) {
      if (options.verbose) {
        logger.warn(`Could not export features for ${pkg.name}: ${(err as Error).message}`);
      }
    }
  }

  if (lines.length > 0) fs.appendFileSync(outPath, lines.join('\n') + '\n');
  return lines.length;
}
