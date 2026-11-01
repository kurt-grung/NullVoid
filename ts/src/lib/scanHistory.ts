/**
 * Scan history persistence and trends.
 * Saves scan results to ~/.nullvoid/history/ and provides trend analysis.
 */

import * as fs from 'fs';
import * as path from 'path';
import type { ScanResult } from '../types/core';

const HISTORY_DIR = path.join(
  process.env['HOME'] || process.env['USERPROFILE'] || process.cwd(),
  '.nullvoid',
  'history'
);

function ensureHistoryDir(): string {
  if (!fs.existsSync(HISTORY_DIR)) {
    fs.mkdirSync(HISTORY_DIR, { recursive: true });
  }
  return HISTORY_DIR;
}

/**
 * Save a scan result to history.
 */
export function saveScanToHistory(result: ScanResult, target: string): string {
  const dir = ensureHistoryDir();
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const safeTarget = target.replace(/[/\\]/g, '_').slice(0, 50) || 'scan';
  const filename = `${ts}_${safeTarget}.json`;
  const filepath = path.join(dir, filename);

  const record = {
    timestamp: new Date().toISOString(),
    target,
    summary: result.summary,
    riskAssessment: result.riskAssessment,
    threatCount: result.threats.length,
    severityCounts: countBySeverity(result.threats),
    threatTypes: [...new Set(result.threats.map((t) => t.type))],
  };

  fs.writeFileSync(filepath, JSON.stringify(record, null, 2));
  return filepath;
}

function countBySeverity(threats: { severity: string }[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const t of threats) {
    counts[t.severity] = (counts[t.severity] ?? 0) + 1;
  }
  return counts;
}

export interface HistoryEntry {
  file: string;
  timestamp: string;
  target: string;
  threatCount: number;
  severityCounts: Record<string, number>;
  riskOverall?: number;
}

/**
 * Load scan history entries (most recent first).
 */
export function loadScanHistory(limit: number = 50): HistoryEntry[] {
  const dir = ensureHistoryDir();
  if (!fs.existsSync(dir)) return [];

  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.json'));
  const entries: HistoryEntry[] = [];

  for (const f of files) {
    try {
      const filepath = path.join(dir, f);
      const content = fs.readFileSync(filepath, 'utf8');
      const record = JSON.parse(content) as {
        timestamp?: string;
        target?: string;
        threatCount?: number;
        severityCounts?: Record<string, number>;
        riskAssessment?: { overall?: number };
      };
      const entry: HistoryEntry = {
        file: filepath,
        timestamp: record.timestamp ?? '',
        target: record.target ?? 'unknown',
        threatCount: record.threatCount ?? 0,
        severityCounts: record.severityCounts ?? {},
      };
      if (record.riskAssessment?.overall != null) {
        entry.riskOverall = record.riskAssessment.overall;
      }
      entries.push(entry);
    } catch {
      /* skip invalid files */
    }
  }

  entries.sort((a, b) => (b.timestamp > a.timestamp ? 1 : -1));
  return entries.slice(0, limit);
}

/**
 * Generate a simple ASCII trend chart for threats over time.
 */
export function formatTrendsReport(entries: HistoryEntry[]): string {
  if (entries.length === 0) {
    return 'No scan history found. Run scans with --save-history to build history.';
  }

  let out = '\n📈 NullVoid Scan Trends\n\n';
  out += 'Recent scans (threats over time):\n\n';

  const maxThreats = Math.max(...entries.map((e) => e.threatCount), 1);
  const barWidth = 20;

  for (const e of entries.slice(0, 14)) {
    const date = e.timestamp ? new Date(e.timestamp).toLocaleDateString() : '?';
    const barLen = Math.round((e.threatCount / maxThreats) * barWidth);
    const bar = '█'.repeat(barLen) + '░'.repeat(barWidth - barLen);
    out += `  ${date}  ${bar}  ${e.threatCount} threats  ${e.target}\n`;
  }

  out += '\nSeverity distribution (last 14 scans):\n\n';
  const severityTotals: Record<string, number> = {};
  for (const e of entries.slice(0, 14)) {
    for (const [sev, count] of Object.entries(e.severityCounts)) {
      severityTotals[sev] = (severityTotals[sev] ?? 0) + count;
    }
  }
  const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  for (const sev of order) {
    const n = severityTotals[sev] ?? 0;
    if (n > 0) out += `  ${sev}: ${n}\n`;
  }

  if (entries.some((e) => e.riskOverall != null && e.riskOverall > 0)) {
    out += '\nRisk trend:\n';
    const recent = entries.slice(0, 7);
    for (const e of recent) {
      const r = (e.riskOverall ?? 0) * 100;
      out += `  ${e.timestamp ? new Date(e.timestamp).toLocaleDateString() : '?'}: ${r.toFixed(1)}%\n`;
    }
  }

  out += `\nHistory: ${path.join(HISTORY_DIR)}\n`;
  return out;
}
