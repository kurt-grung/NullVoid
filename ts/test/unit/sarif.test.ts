import { describe, it, expect } from '@jest/globals';
import { generateSarifOutput } from '../../src/lib/sarif';
import { computeCompositeRisk } from '../../src/lib/riskScoring';
import type { Threat } from '../../src/types/core';

function makeThreat(overrides: Partial<Threat> = {}): Threat {
  return {
    type: 'OBFUSCATED_CODE',
    message: 'Obfuscated code detected',
    severity: 'HIGH',
    confidence: 0.85,
    filePath: 'index.js',
    filename: 'index.js',
    details: 'hex array pattern found',
    ...overrides,
  };
}

describe('generateSarifOutput', () => {
  it('emits a valid SARIF 2.1 envelope', () => {
    const sarif = generateSarifOutput([makeThreat()], { toolVersion: '2.1.0' });

    expect(sarif.version).toBe('2.1.0');
    expect(sarif.$schema).toContain('sarif-schema-2.1.0.json');
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0]?.tool.driver.name).toBe('NullVoid');
    expect(sarif.runs[0]?.tool.driver.version).toBe('2.1.0');
  });

  it('carries composite C/I/A risk on the run', () => {
    const threats = [
      makeThreat({ type: 'DATA_EXFILTRATION', severity: 'CRITICAL' }),
      makeThreat({ type: 'CRYPTO_MINING', severity: 'MEDIUM' }),
    ];

    const sarif = generateSarifOutput(threats);
    const assessment = sarif.runs[0]?.properties.riskAssessment;

    expect(assessment?.overall).toBeGreaterThan(0);
    expect(assessment?.byCategory.confidentiality).toBeGreaterThan(0);
    expect(assessment?.byCategory.availability).toBeGreaterThan(0);
    expect(assessment).toEqual(computeCompositeRisk(threats));
  });

  it('prefers a supplied risk assessment over recomputing', () => {
    const supplied = computeCompositeRisk([makeThreat({ severity: 'CRITICAL' })]);
    const sarif = generateSarifOutput([makeThreat({ severity: 'LOW' })], {
      riskAssessment: supplied,
    });

    expect(sarif.runs[0]?.properties.riskAssessment).toEqual(supplied);
  });

  it('tags each rule with its risk category and security severity', () => {
    const sarif = generateSarifOutput([
      makeThreat({ type: 'DATA_EXFILTRATION', severity: 'CRITICAL' }),
    ]);
    const rule = sarif.runs[0]?.tool.driver.rules[0];

    expect(rule?.id).toBe('DATA_EXFILTRATION');
    expect(rule?.properties.riskCategory).toBe('confidentiality');
    expect(rule?.properties.tags).toEqual(['security', 'risk/confidentiality']);
    expect(rule?.properties['security-severity']).toBe('10.0');
    expect(rule?.defaultConfiguration.level).toBe('error');
  });

  it('derives rule severity from the worst threat of that type', () => {
    const sarif = generateSarifOutput([
      makeThreat({ type: 'MALICIOUS_CODE', severity: 'LOW' }),
      makeThreat({ type: 'MALICIOUS_CODE', severity: 'CRITICAL' }),
    ]);

    expect(sarif.runs[0]?.tool.driver.rules).toHaveLength(1);
    expect(sarif.runs[0]?.tool.driver.rules[0]?.defaultConfiguration.level).toBe('error');
    expect(sarif.runs[0]?.tool.driver.rules[0]?.properties['security-severity']).toBe('10.0');
  });

  it('maps severities to SARIF levels per result', () => {
    const sarif = generateSarifOutput([
      makeThreat({ type: 'MALICIOUS_CODE', severity: 'CRITICAL' }),
      makeThreat({ type: 'SUSPICIOUS_FILE', severity: 'MEDIUM' }),
      makeThreat({ type: 'SUSPICIOUS_SCRIPT', severity: 'LOW' }),
    ]);

    expect(sarif.runs[0]?.results.map((r) => r.level)).toEqual(['error', 'warning', 'note']);
  });

  it('includes a region only when a line number is known', () => {
    const sarif = generateSarifOutput([
      makeThreat({ lineNumber: 42 }),
      makeThreat({ type: 'SUSPICIOUS_FILE' }),
    ]);

    expect(sarif.runs[0]?.results[0]?.locations[0]?.physicalLocation.region).toEqual({
      startLine: 42,
      startColumn: 1,
    });
    expect(sarif.runs[0]?.results[1]?.locations[0]?.physicalLocation.region).toBeUndefined();
  });

  it('relativizes absolute paths against the workspace root', () => {
    const sarif = generateSarifOutput([makeThreat({ filePath: '/repo/src/evil.js' })], {
      workspaceRoot: '/repo',
    });

    expect(sarif.runs[0]?.results[0]?.locations[0]?.physicalLocation.artifactLocation.uri).toBe(
      'src/evil.js'
    );
  });

  it('falls back to the basename for paths outside the workspace root', () => {
    const sarif = generateSarifOutput([makeThreat({ filePath: '/elsewhere/evil.js' })], {
      workspaceRoot: '/repo',
    });

    expect(sarif.runs[0]?.results[0]?.locations[0]?.physicalLocation.artifactLocation.uri).toBe(
      'evil.js'
    );
  });

  it('strips terminal decoration from reported paths', () => {
    const sarif = generateSarifOutput([
      makeThreat({ filePath: '\u001b[36m📦 node_modules/evil/index.js\u001b[0m' }),
    ]);

    expect(sarif.runs[0]?.results[0]?.locations[0]?.physicalLocation.artifactLocation.uri).toBe(
      'node_modules/evil/index.js'
    );
  });

  it('produces stable fingerprints for identical findings and distinct ones otherwise', () => {
    const [first] = generateSarifOutput([makeThreat({ lineNumber: 10 })]).runs[0]?.results ?? [];
    const [repeat] = generateSarifOutput([makeThreat({ lineNumber: 10 })]).runs[0]?.results ?? [];
    const [moved] = generateSarifOutput([makeThreat({ lineNumber: 11 })]).runs[0]?.results ?? [];

    expect(first?.partialFingerprints.nullvoidThreat).toBe(repeat?.partialFingerprints.nullvoidThreat);
    expect(first?.partialFingerprints.nullvoidThreat).not.toBe(
      moved?.partialFingerprints.nullvoidThreat
    );
  });

  it('normalizes percentage confidence onto a 0-1 scale', () => {
    const sarif = generateSarifOutput([makeThreat({ confidence: 85 })]);

    expect(sarif.runs[0]?.results[0]?.properties.confidence).toBeCloseTo(0.85);
  });

  it('reports a clean run for an empty threat list', () => {
    const sarif = generateSarifOutput([]);
    const run = sarif.runs[0];

    expect(run?.results).toHaveLength(0);
    expect(run?.tool.driver.rules).toHaveLength(0);
    expect(run?.invocations[0]?.exitCode).toBe(0);
    expect(run?.invocations[0]?.exitCodeDescription).toBe('No threats detected');
    expect(run?.properties.riskAssessment.overall).toBe(0);
  });

  it('signals a failing exit code when threats are present', () => {
    const sarif = generateSarifOutput([makeThreat()]);

    expect(sarif.runs[0]?.invocations[0]?.exitCode).toBe(1);
    expect(sarif.runs[0]?.invocations[0]?.exitCodeDescription).toBe('Threats detected');
  });
});
