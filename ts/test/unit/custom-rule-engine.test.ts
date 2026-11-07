import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { describe, it, expect } from '@jest/globals';
import { runCustomRuleEngine, resolveScanRules, detectFileThreats } from '../../src/lib/customRuleEngine';
import { detectMalware } from '../../src/lib/detection';

describe('customRuleEngine', () => {
  it('matches enhanced wallet hijacking patterns', () => {
    const content = 'window.ethereum = new Proxy(window.ethereum, {})';
    const threats = runCustomRuleEngine(content, 'pkg/index.js');
    expect(threats.length).toBeGreaterThan(0);
    expect(threats[0]?.type).toContain('WALLET_HIJACKING');
  });

  it('resolveScanRules applies built-in rules when no custom rules are configured', () => {
    const rules = resolveScanRules({});
    expect(rules).toBeDefined();
    expect(rules?.['wallet_hijacking']).toBeDefined();
  });

  it('resolveScanRules returns undefined when builtinRules is false', () => {
    expect(resolveScanRules({ builtinRules: false })).toBeUndefined();
  });

  it('detectFileThreats flags a wallet proxy with default options', () => {
    const content = 'window.ethereum = new Proxy(window.ethereum, { get: () => {} });';
    const threats = detectFileThreats(content, 'pkg/index.js', {}, detectMalware);
    expect(threats.some((t) => t.type.includes('WALLET_HIJACKING'))).toBe(true);
  });

  it('detectFileThreats skips built-in rules when builtinRules is false', () => {
    const content = 'window.ethereum = new Proxy(window.ethereum, { get: () => {} });';
    const threats = detectFileThreats(content, 'pkg/index.js', { builtinRules: false }, detectMalware);
    expect(threats.some((t) => t.type.includes('WALLET_HIJACKING'))).toBe(false);
  });

  it('resolveScanRules parses inline rules', () => {
    const rules = resolveScanRules({
      rules: {
        acme_rule: {
          patterns: ['acme-secret-token'],
          severity: 'HIGH',
          description: 'ACME token',
          confidence_threshold: 0.8,
        },
      },
      mergeRulesWithDefaults: false,
    });
    expect(rules?.['acme_rule']?.patterns).toEqual(['acme-secret-token']);
  });

  it('detectFileThreats merges custom rule hits with base detection', () => {
    const content = 'const token = "acme-secret-token";';
    const threats = detectFileThreats(content, 'pkg/index.js', {
      rules: {
        acme_rule: {
          patterns: ['acme-secret-token'],
          severity: 'HIGH',
          description: 'ACME token',
          confidence_threshold: 0.8,
        },
      },
      mergeRulesWithDefaults: false,
    }, detectMalware);
    expect(threats.some((t) => t.type.includes('ACME_RULE'))).toBe(true);
  });

  it('loads rules from a file path', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nullvoid-rules-'));
    const rulesPath = path.join(dir, 'rules.json');
    fs.writeFileSync(
      rulesPath,
      JSON.stringify({
        detection_rules: {
          file_rule: {
            patterns: ['file-only-pattern'],
            severity: 'MEDIUM',
            description: 'from file',
            confidence_threshold: 0.6,
          },
        },
      })
    );
    const threats = runCustomRuleEngine('file-only-pattern here', 'pkg/a.js', {
      rulesPath,
      mergeWithDefaults: false,
    });
    expect(threats.length).toBeGreaterThan(0);
    fs.rmSync(dir, { recursive: true, force: true });
  });
});
