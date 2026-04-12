/**
 * Markdown report generator for scan results.
 */

import type { ScanResult, Threat } from '../../types/core';

const SEVERITY_EMOJI: Record<string, string> = {
  CRITICAL: '🔴',
  HIGH: '🟠',
  MEDIUM: '🟡',
  LOW: '🟢',
};

function escapeMd(text: string): string {
  return text.replace(/[\\`*_[#]/g, '\\$&');
}

function formatThreat(t: Threat): string {
  const emoji = SEVERITY_EMOJI[t.severity] ?? '⚪';
  let block = `### ${emoji} ${escapeMd(t.type)} (${t.severity})\n\n`;
  block += `- **Message:** ${escapeMd(t.message)}\n`;
  if (t.details) block += `- **Details:** ${escapeMd(t.details)}\n`;
  if (t.filePath) block += `- **File:** \`${t.filePath}\`\n`;
  if (t.lineNumber) block += `- **Line:** ${t.lineNumber}\n`;
  if (t.confidence != null) block += `- **Confidence:** ${(t.confidence * 100).toFixed(0)}%\n`;
  if (Array.isArray((t as { topFactors?: unknown[] }).topFactors)) {
    const topFactors = ((t as { topFactors?: string[] }).topFactors ?? []).slice(0, 3);
    if (topFactors.length > 0) {
      block += `- **Top factors:** ${topFactors.map((f) => `\`${escapeMd(String(f))}\``).join(', ')}\n`;
    }
  }
  return block;
}

function getSoc2Controls(threatType: string): string[] {
  if (
    threatType.includes('DATA_EXFILTRATION') ||
    threatType.includes('PATH_TRAVERSAL') ||
    threatType.includes('WALLET_')
  ) {
    return ['CC6.1'];
  }
  if (
    threatType.includes('CRYPTO_MINING') ||
    threatType.includes('TIMEOUT') ||
    threatType.includes('MEMORY') ||
    threatType.includes('SANDBOX_')
  ) {
    return ['CC9.1'];
  }
  return ['CC7.1'];
}

function getIsoControls(threatType: string): string[] {
  if (threatType.includes('DEPENDENCY_CONFUSION') || threatType.includes('SUPPLY_CHAIN')) {
    return ['A.15.2.1'];
  }
  if (threatType.includes('MALICIOUS') || threatType.includes('OBFUSCATED')) {
    return ['A.12.2.1'];
  }
  if (threatType.includes('DATA_EXFILTRATION') || threatType.includes('PATH_TRAVERSAL')) {
    return ['A.9.4.1'];
  }
  return ['A.14.2.1'];
}

function getComplianceSection(compliance: 'soc2' | 'iso27001', threats: Threat[]): string {
  const threatTypes = [...new Set(threats.map((t) => t.type))];
  if (compliance === 'soc2') {
    return `
## SOC 2 Control Mapping

| Threat Type | CC6.1 (Logical Access) | CC7.1 (Detection) | CC9.1 (Availability) |
|-------------|------------------------|-------------------|----------------------|
${threatTypes
  .map((tt) => {
    const controls = getSoc2Controls(tt);
    return `| ${tt} | ${controls.includes('CC6.1') ? '✓' : ''} | ${controls.includes('CC7.1') ? '✓' : ''} | ${controls.includes('CC9.1') ? '✓' : ''} |`;
  })
  .join('\n')}

*This scan maps threat classes to SOC 2 CC6.1, CC7.1, and CC9.1 controls.*
`;
  }
  if (compliance === 'iso27001') {
    return `
## ISO 27001 Control Mapping

| Threat Type | A.15.2.1 (Supplier Relationships) | A.12.2.1 (Malware Controls) | A.9.4.1 (Access Restriction) | A.14.2.1 (Secure Development) |
|-------------|------------------------------------|------------------------------|------------------------------|-------------------------------|
${threatTypes
  .map((tt) => {
    const controls = getIsoControls(tt);
    return `| ${tt} | ${controls.includes('A.15.2.1') ? '✓' : ''} | ${controls.includes('A.12.2.1') ? '✓' : ''} | ${controls.includes('A.9.4.1') ? '✓' : ''} | ${controls.includes('A.14.2.1') ? '✓' : ''} |`;
  })
  .join('\n')}

*This scan maps threat classes to ISO 27001 A.15.2.1, A.12.2.1, A.9.4.1, and A.14.2.1 controls.*
`;
  }
  return '';
}

export function generateMarkdownReport(
  result: ScanResult,
  options?: { compliance?: 'soc2' | 'iso27001' }
): string {
  const { threats, summary, riskAssessment, metadata } = result;
  const target = (metadata?.['target'] as string) ?? 'unknown';
  const scanTime = (metadata?.['scanTime'] as string) ?? new Date().toISOString();

  let md = `# NullVoid Security Scan Report\n\n`;
  md += `**Target:** ${escapeMd(target)}\n`;
  md += `**Scan Time:** ${scanTime}\n`;
  md += `**Threats Found:** ${summary.threatsFound}\n`;
  md += `**Files Scanned:** ${summary.totalFiles}\n`;
  md += `**Packages Scanned:** ${summary.totalPackages}\n`;
  md += `**Duration:** ${summary.scanDuration}ms\n\n`;

  if (riskAssessment) {
    md += `## Risk Assessment\n\n`;
    md += `- **Overall Risk:** ${(riskAssessment.overall * 100).toFixed(1)}%\n`;
    if (riskAssessment.byCategory) {
      md += `- **By Category:**\n`;
      for (const [cat, val] of Object.entries(riskAssessment.byCategory)) {
        md += `  - ${cat}: ${(Number(val) * 100).toFixed(1)}%\n`;
      }
    }
    md += `\n`;
  }

  if (threats.length === 0) {
    md += `## ✅ No threats detected\n\n`;
  } else {
    md += `## Threats (${threats.length})\n\n`;
    threats.forEach((t) => {
      md += formatThreat(t) + '\n';
    });
  }

  if (options?.compliance) {
    md += getComplianceSection(options.compliance, threats);
  }

  return md;
}
