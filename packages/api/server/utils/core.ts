/**
 * Business logic shared with the Express app, imported straight from src/ so the Nitro
 * bundler (and Vercel's file tracing) can follow every dependency. The heavy `nullvoid`
 * engine stays lazy: dynamic import() keeps it in its own chunk, loaded on first use.
 */
export * as db from '../../src/db';
export * as scanTarget from '../../src/scanTarget';
export * as customRules from '../../src/customRules';
export * as store from '../../src/enterprise/store';
export * as enterpriseTypes from '../../src/enterprise/types';
export * as jobs from '../../src/enterprise/jobs';

type ScanFn = (target: string, options?: object) => Promise<unknown>;

/** Lazy-load the scan engine (heavy) - only when POST /scan runs */
export async function getScanFn(): Promise<ScanFn> {
  const mod = (await import('nullvoid/dist/scan')) as unknown as { scan: ScanFn };
  return mod.scan;
}

/** Lazy-load the ML risk helper; never throws, null when no ML service is reachable */
export async function getPackageMlRisk(packageName: string): Promise<unknown> {
  try {
    const mod = (await import('nullvoid/dist/lib/mlRiskScore')) as unknown as {
      computePackageMlRisk: (name: string) => Promise<unknown>;
    };
    return await mod.computePackageMlRisk(packageName);
  } catch {
    return null;
  }
}

type ReportOpts = { compliance?: 'soc2' | 'iso27001' };

export async function getReporting() {
  return (await import('nullvoid/dist/lib/reporting')) as unknown as {
    generateHtmlReport: (r: unknown, o?: ReportOpts) => string;
    generateMarkdownReport: (r: unknown, o?: ReportOpts) => string;
  };
}

export function newAuditId(): string {
  return `audit-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}
