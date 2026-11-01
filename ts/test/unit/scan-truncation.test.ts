import {
  buildScanTruncationReport,
  formatScanTruncationLines,
  truncationCap,
} from '../../src/lib/scanTruncation';

describe('scanTruncation', () => {
  it('builds a report when any cap is exceeded', () => {
    const report = buildScanTruncationReport([
      truncationCap('iocQueriesPerScan', 30, 30, 45),
      truncationCap('projectPackageRoots', 50, 50, 50),
    ]);
    expect(report).toEqual({
      partialCoverage: true,
      caps: [{ id: 'iocQueriesPerScan', limit: 30, processed: 30, skipped: 15 }],
    });
  });

  it('formats cap lines for CLI output', () => {
    const report = buildScanTruncationReport([
      truncationCap('dependencyConfusionPackages', 30, 30, 40),
    ]);
    expect(report).toBeDefined();
    const lines = formatScanTruncationLines(report as NonNullable<typeof report>);
    expect(lines[0]).toContain('dependency confusion targets');
    expect(lines[0]).toContain('skipped 10');
  });
});
