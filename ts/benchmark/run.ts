#!/usr/bin/env node
/**
 * Detection benchmark.
 *
 * Scans a labelled corpus and reports precision / recall at the package level:
 *   - benchmark/malicious/<pkg>   fixtures reconstructing real incidents (positives)
 *   - benchmark/benign.json       pinned npm packages, fetched into benchmark/.cache (negatives)
 *
 * A package is "detected" when the scanner reports at least one threat at or
 * above --threshold (default HIGH). Exits non-zero when recall or precision
 * fall below --min-recall / --min-precision, or when they regress against a
 * --baseline JSON (benchmark/baseline.json by default, if present).
 *
 *   npm run benchmark                        # full run, writes benchmark/results.json
 *   npm run benchmark -- --offline           # skip packages not already cached
 *   npm run benchmark -- --update-baseline   # accept the current numbers as the new floor
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { execFileSync } from 'child_process';
import { scan } from '../src/scan';
import type { SeverityLevel, Threat } from '../src/types/core';

const ROOT = path.resolve(__dirname);
const MALICIOUS_DIR = path.join(ROOT, 'malicious');
const CACHE_DIR = path.join(ROOT, '.cache');
const RESULTS_PATH = path.join(ROOT, 'results.json');
const BASELINE_PATH = path.join(ROOT, 'baseline.json');

const SEVERITY_RANK: Record<SeverityLevel, number> = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

interface Args {
  threshold: SeverityLevel;
  minRecall: number;
  minPrecision: number;
  offline: boolean;
  updateBaseline: boolean;
  baseline: string | undefined;
  verbose: boolean;
}

function parseArgs(argv: string[]): Args {
  const args: Args = {
    threshold: 'HIGH',
    minRecall: 0.9,
    minPrecision: 0.8,
    offline: false,
    updateBaseline: false,
    baseline: fs.existsSync(BASELINE_PATH) ? BASELINE_PATH : undefined,
    verbose: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = (): string => {
      i += 1;
      const v = argv[i];
      if (v === undefined) throw new Error(`missing value for ${a}`);
      return v;
    };
    if (a === '--threshold') args.threshold = next().toUpperCase() as SeverityLevel;
    else if (a === '--min-recall') args.minRecall = Number(next());
    else if (a === '--min-precision') args.minPrecision = Number(next());
    else if (a === '--offline') args.offline = true;
    else if (a === '--update-baseline') args.updateBaseline = true;
    else if (a === '--baseline') args.baseline = next();
    else if (a === '--no-baseline') args.baseline = undefined;
    else if (a === '--verbose' || a === '-v') args.verbose = true;
  }
  return args;
}

interface PackageResult {
  name: string;
  label: 'malicious' | 'benign';
  detected: boolean;
  maxSeverity: SeverityLevel | null;
  threatTypes: string[];
  filesScanned: number;
  note?: string;
}

interface BenchmarkResults {
  generatedAt: string;
  threshold: SeverityLevel;
  counts: { tp: number; fn: number; fp: number; tn: number; skipped: number };
  precision: number;
  recall: number;
  f1: number;
  byThreatType: Record<string, number>;
  packages: PackageResult[];
}

function maxSeverity(threats: Threat[]): SeverityLevel | null {
  let best: SeverityLevel | null = null;
  for (const t of threats) {
    if (!best || SEVERITY_RANK[t.severity] > SEVERITY_RANK[best]) best = t.severity;
  }
  return best;
}

async function scanPackage(dir: string): Promise<{ threats: Threat[]; filesScanned: number }> {
  const result = await scan(dir, {
    all: true,
    iocEnabled: false,
    dependencyConfusionEnabled: false,
    scanDependencySource: false,
    saveHistory: false,
  });
  return { threats: result.threats, filesScanned: result.filesScanned ?? 0 };
}

function ensureBenign(spec: string, offline: boolean): string | undefined {
  const safeName = spec.replace(/[@/]/g, '_');
  const dest = path.join(CACHE_DIR, safeName);
  if (fs.existsSync(path.join(dest, 'package', 'package.json'))) return path.join(dest, 'package');
  if (offline) return undefined;

  fs.mkdirSync(dest, { recursive: true });
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'nv-bench-'));
  try {
    const out = execFileSync('npm', ['pack', spec, '--pack-destination', tmp, '--ignore-scripts'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    const tarball = path.join(tmp, out.split('\n').pop() || '');
    execFileSync('tar', ['-xzf', tarball, '-C', dest]);
    return path.join(dest, 'package');
  } catch (error) {
    console.error(`  ! could not fetch ${spec}: ${(error as Error).message.split('\n')[0]}`);
    return undefined;
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const threshold = SEVERITY_RANK[args.threshold];
  const results: PackageResult[] = [];
  const byThreatType: Record<string, number> = {};

  // --- positives
  const manifest = JSON.parse(
    fs.readFileSync(path.join(MALICIOUS_DIR, 'manifest.json'), 'utf8')
  ) as {
    packages: { name: string; incident: string; expect: string[] }[];
  };
  console.log(`Malicious corpus: ${manifest.packages.length} packages`);
  for (const entry of manifest.packages) {
    const dir = path.join(MALICIOUS_DIR, entry.name);
    const { threats, filesScanned } = await scanPackage(dir);
    const sev = maxSeverity(threats);
    const detected = sev !== null && SEVERITY_RANK[sev] >= threshold;
    const types = [...new Set(threats.map((t) => String(t.type)))];
    for (const t of types) byThreatType[t] = (byThreatType[t] ?? 0) + 1;
    results.push({
      name: entry.name,
      label: 'malicious',
      detected,
      maxSeverity: sev,
      threatTypes: types,
      filesScanned,
    });
    if (args.verbose || !detected) {
      console.log(
        `  ${detected ? '✓' : '✗ MISSED'} ${entry.name} (${entry.incident}) -> ${sev ?? 'none'} ${types.join(',')}`
      );
    }
  }

  // --- negatives
  const benign = JSON.parse(fs.readFileSync(path.join(ROOT, 'benign.json'), 'utf8')) as {
    packages: string[];
  };
  console.log(
    `Benign corpus: ${benign.packages.length} packages${args.offline ? ' (offline: cached only)' : ''}`
  );
  let skipped = 0;
  for (const spec of benign.packages) {
    const dir = ensureBenign(spec, args.offline);
    if (!dir) {
      skipped += 1;
      results.push({
        name: spec,
        label: 'benign',
        detected: false,
        maxSeverity: null,
        threatTypes: [],
        filesScanned: 0,
        note: 'skipped: not cached',
      });
      continue;
    }
    const { threats, filesScanned } = await scanPackage(dir);
    const sev = maxSeverity(threats);
    const detected = sev !== null && SEVERITY_RANK[sev] >= threshold;
    const flagged = threats.filter((t) => SEVERITY_RANK[t.severity] >= threshold);
    const types = [...new Set(flagged.map((t) => String(t.type)))];
    results.push({
      name: spec,
      label: 'benign',
      detected,
      maxSeverity: sev,
      threatTypes: types,
      filesScanned,
    });
    if (args.verbose || detected) {
      console.log(
        `  ${detected ? '✗ FALSE POSITIVE' : '✓'} ${spec} (${filesScanned} files) -> ${sev ?? 'none'} ${types.join(',')}`
      );
      if (detected) {
        for (const t of flagged.slice(0, 5)) {
          console.log(
            `      ${t.type} ${t.severity} ${path.relative(dir, t.filePath)}${t.lineNumber ? ':' + t.lineNumber : ''} — ${t.message}`
          );
        }
      }
    }
  }

  // --- metrics
  const scored = results.filter((r) => !r.note);
  const tp = scored.filter((r) => r.label === 'malicious' && r.detected).length;
  const fn = scored.filter((r) => r.label === 'malicious' && !r.detected).length;
  const fp = scored.filter((r) => r.label === 'benign' && r.detected).length;
  const tn = scored.filter((r) => r.label === 'benign' && !r.detected).length;
  const precision = tp + fp === 0 ? 1 : tp / (tp + fp);
  const recall = tp + fn === 0 ? 1 : tp / (tp + fn);
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);

  const out: BenchmarkResults = {
    generatedAt: new Date().toISOString(),
    threshold: args.threshold,
    counts: { tp, fn, fp, tn, skipped },
    precision: Number(precision.toFixed(4)),
    recall: Number(recall.toFixed(4)),
    f1: Number(f1.toFixed(4)),
    byThreatType,
    packages: results,
  };
  fs.writeFileSync(RESULTS_PATH, JSON.stringify(out, null, 2) + '\n');

  console.log('');
  console.log(
    `threshold ${args.threshold}: tp=${tp} fn=${fn} fp=${fp} tn=${tn}${skipped ? ` skipped=${skipped}` : ''}`
  );
  console.log(
    `precision ${(precision * 100).toFixed(1)}%  recall ${(recall * 100).toFixed(1)}%  f1 ${(f1 * 100).toFixed(1)}%`
  );
  console.log(`results written to ${path.relative(process.cwd(), RESULTS_PATH)}`);

  // --- gates
  const failures: string[] = [];
  if (recall < args.minRecall) failures.push(`recall ${recall.toFixed(3)} < ${args.minRecall}`);
  if (precision < args.minPrecision)
    failures.push(`precision ${precision.toFixed(3)} < ${args.minPrecision}`);

  if (args.updateBaseline) {
    fs.writeFileSync(
      BASELINE_PATH,
      JSON.stringify(
        { precision: out.precision, recall: out.recall, threshold: out.threshold },
        null,
        2
      ) + '\n'
    );
    console.log(`baseline updated: ${path.relative(process.cwd(), BASELINE_PATH)}`);
  } else if (args.baseline && fs.existsSync(args.baseline)) {
    const base = JSON.parse(fs.readFileSync(args.baseline, 'utf8')) as {
      precision: number;
      recall: number;
    };
    const eps = 1e-6;
    if (recall + eps < base.recall)
      failures.push(`recall regressed: ${recall.toFixed(3)} < baseline ${base.recall}`);
    if (precision + eps < base.precision)
      failures.push(`precision regressed: ${precision.toFixed(3)} < baseline ${base.precision}`);
  }

  if (failures.length > 0) {
    console.error('\nBENCHMARK FAILED:');
    for (const f of failures) console.error(`  - ${f}`);
    process.exit(1);
  }
  console.log('benchmark: ok');
}

main().catch((error) => {
  console.error(error);
  process.exit(2);
});
