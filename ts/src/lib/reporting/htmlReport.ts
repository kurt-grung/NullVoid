/**
 * HTML report generator for scan results.
 */

import type { ScanResult, Threat } from '../../types/core';

const SEVERITY_CLASS: Record<string, string> = {
  CRITICAL: 'severity-critical',
  HIGH: 'severity-high',
  MEDIUM: 'severity-medium',
  LOW: 'severity-low',
};

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function formatThreatRow(t: Threat): string {
  const cls = SEVERITY_CLASS[t.severity] ?? '';
  const confidence = t.confidence != null ? `${(t.confidence * 100).toFixed(0)}%` : '-';
  return `<tr class="${cls}">
  <td>${escapeHtml(t.type)}</td>
  <td>${escapeHtml(t.severity)}</td>
  <td>${escapeHtml(t.message)}</td>
  <td>${escapeHtml(t.filePath || '-')}</td>
  <td>${confidence}</td>
</tr>`;
}

function getComplianceSection(compliance: 'soc2' | 'iso27001', threats: Threat[]): string {
  const threatTypes = [...new Set(threats.map((t) => t.type))];
  const rows = threatTypes
    .map((tt) => `<tr><td>${escapeHtml(tt)}</td><td>✓</td><td>✓</td></tr>`)
    .join('');
  if (compliance === 'soc2') {
    return `
<section class="compliance">
  <h2>SOC 2 Control Mapping</h2>
  <table>
    <thead><tr><th>Threat Type</th><th>CC6.1</th><th>CC7.1</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
  <p>This scan supports detection relevant to SOC 2 CC6.1 (logical access) and CC7.1 (security event monitoring).</p>
</section>`;
  }
  if (compliance === 'iso27001') {
    return `
<section class="compliance">
  <h2>ISO 27001 Control Mapping</h2>
  <table>
    <thead><tr><th>Threat Type</th><th>A.12.6.1</th><th>A.14.2.1</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
  <p>This scan supports detection relevant to ISO 27001 A.12.6.1 and A.14.2.1.</p>
</section>`;
  }
  return '';
}

export function generateHtmlReport(
  result: ScanResult,
  options?: { compliance?: 'soc2' | 'iso27001' }
): string {
  const { threats, summary, riskAssessment, metadata } = result;
  const target = (metadata?.['target'] as string) ?? 'unknown';
  const scanTime = (metadata?.['scanTime'] as string) ?? new Date().toISOString();

  const threatRows = threats.map(formatThreatRow).join('');

  const riskSection = riskAssessment
    ? `
<section class="risk">
  <h2>Risk Assessment</h2>
  <p><strong>Overall Risk:</strong> ${(riskAssessment.overall * 100).toFixed(1)}%</p>
  ${
    riskAssessment.byCategory
      ? `<ul>${Object.entries(riskAssessment.byCategory)
          .map(([k, v]) => `<li>${k}: ${(Number(v) * 100).toFixed(1)}%</li>`)
          .join('')}</ul>`
      : ''
  }
</section>`
    : '';

  const complianceSection = options?.compliance
    ? getComplianceSection(options.compliance, threats)
    : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NullVoid Security Scan - ${escapeHtml(target)}</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: system-ui, -apple-system, sans-serif; max-width: 900px; margin: 0 auto; padding: 2rem; }
    h1 { color: #1a1a2e; }
    .summary { background: #f5f5f5; padding: 1rem; border-radius: 8px; margin: 1rem 0; }
    .summary p { margin: 0.25rem 0; }
    table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
    th, td { padding: 0.5rem; text-align: left; border-bottom: 1px solid #ddd; }
    th { background: #1a1a2e; color: white; }
    .severity-critical { background: #ffebee; }
    .severity-high { background: #fff3e0; }
    .severity-medium { background: #fffde7; }
    .severity-low { background: #e8f5e9; }
    .risk, .compliance { margin: 2rem 0; }
    .no-threats { color: #2e7d32; font-weight: bold; }
  </style>
</head>
<body>
  <h1>NullVoid Security Scan Report</h1>
  <div class="summary">
    <p><strong>Target:</strong> ${escapeHtml(target)}</p>
    <p><strong>Scan Time:</strong> ${scanTime}</p>
    <p><strong>Threats Found:</strong> ${summary.threatsFound}</p>
    <p><strong>Files Scanned:</strong> ${summary.totalFiles}</p>
    <p><strong>Packages Scanned:</strong> ${summary.totalPackages}</p>
    <p><strong>Duration:</strong> ${summary.scanDuration}ms</p>
  </div>
  ${riskSection}
  <h2>Threats</h2>
  ${
    threats.length === 0
      ? '<p class="no-threats">✅ No threats detected</p>'
      : `
  <table>
    <thead><tr><th>Type</th><th>Severity</th><th>Message</th><th>File</th><th>Confidence</th></tr></thead>
    <tbody>${threatRows}</tbody>
  </table>`
  }
  ${complianceSection}
</body>
</html>`;
}
