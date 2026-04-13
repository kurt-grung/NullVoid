import { describe, it, expect } from '@jest/globals';
import { generateSarifOutput } from '../../src/lib/sarif';
import type { Threat } from '../../src/types/core';

describe('generateSarifOutput', () => {
  it('returns an object containing the passed threats array', () => {
  const threats: Threat[] = [
    {
      type: 'OBFUSCATED_CODE',
      message: 'Obfuscated code detected',
      severity: 'HIGH',
      confidence: 85,
      package: 'evil-pkg',
      filePath: 'index.js',
      filename: 'index.js',
      details: 'hex array pattern found',
    },
  ];
    const output = generateSarifOutput(threats);
    expect(output).toHaveProperty('threats');
    expect(output.threats).toHaveLength(1);
    expect(output.threats[0]?.type).toBe('OBFUSCATED_CODE');
  });

  it('handles an empty threats array', () => {
    const output = generateSarifOutput([]);
    expect(output.threats).toHaveLength(0);
  });

  it('preserves all threat fields', () => {
    const threat: Threat = {
      type: 'CRYPTO_MINING',
      message: 'Mining script detected',
      severity: 'CRITICAL',
      confidence: 95,
      package: 'crypto-pkg',
      filePath: 'index.js',
      filename: 'index.js',
      details: 'CoinHive miner detected',
      lineNumber: 42,
      sampleCode: 'var miner = new CoinHive.Anonymous()',
    };
    const { threats } = generateSarifOutput([threat]);
    expect(threats[0]).toMatchObject(threat);
  });
});
