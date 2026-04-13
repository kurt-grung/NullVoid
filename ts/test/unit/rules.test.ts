import { describe, it, expect } from '@jest/globals';
import {
  ENHANCED_RULES,
  applyRules,
  mergeRules,
  validateRules,
  loadRules,
  type EnhancedRules,
} from '../../src/lib/rules';

describe('validateRules', () => {
  it('passes validation on the built-in ENHANCED_RULES', () => {
    const { valid, errors } = validateRules(ENHANCED_RULES);
    expect(valid).toBe(true);
    expect(errors).toHaveLength(0);
  });

  it('flags a rule with missing patterns', () => {
    const bad: EnhancedRules = {
      bad_rule: { patterns: null as unknown as string[], severity: 'HIGH', description: 'x', confidence_threshold: 0.8 },
    };
    const { valid, errors } = validateRules(bad);
    expect(valid).toBe(false);
    expect(errors.some((e) => e.includes('bad_rule'))).toBe(true);
  });

  it('flags an invalid confidence_threshold', () => {
    const bad: EnhancedRules = {
      bad_conf: { patterns: ['x'], severity: 'LOW', description: 'y', confidence_threshold: 1.5 },
    };
    const { valid } = validateRules(bad);
    expect(valid).toBe(false);
  });
});

describe('applyRules', () => {
  it('detects a match against a custom rule pattern', () => {
    const rules: EnhancedRules = {
      test_rule: {
        patterns: ['eval\\s*\\('],
        severity: 'HIGH',
        description: 'eval usage',
        confidence_threshold: 0.5,
      },
    };
    const results = applyRules('const x = eval("1+1");', 'test-pkg', rules);
    expect(results.length).toBeGreaterThan(0);
    expect(results[0]?.rule).toBe('test_rule');
  });

  it('returns no results for clean content', () => {
    const rules: EnhancedRules = {
      evil_rule: {
        patterns: ['stolen_wallet_address'],
        severity: 'CRITICAL',
        description: 'wallet theft',
        confidence_threshold: 0.9,
      },
    };
    const results = applyRules('function add(a, b) { return a + b; }', 'clean-pkg', rules);
    expect(results).toHaveLength(0);
  });
});

describe('mergeRules', () => {
  it('custom rule overrides a built-in rule', () => {
    const overrides: EnhancedRules = {
      wallet_hijacking: { patterns: ['customWalletPattern'], severity: 'CRITICAL', description: 'overridden', confidence_threshold: 0.99 },
    };
    const merged = mergeRules(overrides, ENHANCED_RULES);
    expect(merged['wallet_hijacking']?.description).toBe('overridden');
  });

  it('preserves existing built-in rules not present in custom rules', () => {
    const merged = mergeRules({}, ENHANCED_RULES);
    expect(Object.keys(merged).length).toBeGreaterThanOrEqual(Object.keys(ENHANCED_RULES).length);
  });
});

describe('loadRules', () => {
  it('returns ENHANCED_RULES when the path does not exist', () => {
    const rules = loadRules('/nonexistent/path/rules.json');
    expect(rules).toEqual(expect.objectContaining(ENHANCED_RULES));
  });
});
