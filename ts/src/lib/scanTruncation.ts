export type ScanTruncationCapId =
  | 'projectPackageRoots'
  | 'iocQueriesPerScan'
  | 'dependencyConfusionPackages'
  | 'dependencySourcePackages'
  | 'dependencySourceFiles'
  | 'lifecycleScriptPackages';

export interface ScanTruncationCap {
  id: ScanTruncationCapId;
  limit: number;
  processed: number;
  skipped: number;
}

export interface ScanTruncationReport {
  partialCoverage: boolean;
  caps: ScanTruncationCap[];
}

const CAP_LABELS: Record<ScanTruncationCapId, string> = {
  projectPackageRoots: 'project package roots (monorepo package.json dirs)',
  iocQueriesPerScan: 'IoC vulnerability lookups',
  dependencyConfusionPackages: 'dependency confusion targets',
  dependencySourcePackages: 'dependency source packages',
  dependencySourceFiles: 'dependency source files',
  lifecycleScriptPackages: 'lifecycle script package.json files',
};

export function capLabel(id: ScanTruncationCapId): string {
  return CAP_LABELS[id];
}

export function truncationCap(
  id: ScanTruncationCapId,
  limit: number,
  processed: number,
  eligible: number
): ScanTruncationCap | undefined {
  const skipped = Math.max(0, eligible - processed);
  if (skipped <= 0) return undefined;
  return { id, limit, processed, skipped };
}

export function buildScanTruncationReport(
  caps: Array<ScanTruncationCap | undefined>
): ScanTruncationReport | undefined {
  const resolved = caps.filter((cap): cap is ScanTruncationCap => cap !== undefined);
  if (resolved.length === 0) return undefined;
  return { partialCoverage: true, caps: resolved };
}

export function parseScanTruncationReport(
  metadata: Record<string, unknown> | undefined
): ScanTruncationReport | undefined {
  const raw = metadata?.['scanTruncations'];
  if (!raw || typeof raw !== 'object') return undefined;
  const report = raw as ScanTruncationReport;
  if (!Array.isArray(report.caps)) return undefined;
  return report;
}

export function formatScanTruncationLines(report: ScanTruncationReport): string[] {
  return report.caps.map(
    (cap) =>
      `   ${capLabel(cap.id)}: limit ${cap.limit}, analyzed ${cap.processed}, skipped ${cap.skipped}`
  );
}
