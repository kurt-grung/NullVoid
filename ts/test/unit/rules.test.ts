import { describe, it, expect, jest } from '@jest/globals';
import {
  ENHANCED_RULES,
  applyRules,
  mergeRules,
  validateRules,
  loadRules,
  parseRulesObject,
  normalizeRules,
  compileRules,
  unsafeRegexReason,
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
      bad_rule: {
        patterns: null as unknown as string[],
        severity: 'HIGH',
        description: 'x',
        confidence_threshold: 0.8,
      },
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
      wallet_hijacking: {
        patterns: ['customWalletPattern'],
        severity: 'CRITICAL',
        description: 'overridden',
        confidence_threshold: 0.99,
      },
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

describe('parseRulesObject', () => {
  it('extracts detection_rules and normalizes defaults', () => {
    const rules = parseRulesObject({
      detection_rules: {
        custom: {
          patterns: ['evilPattern'],
          severity: 'HIGH',
          description: 'custom threat',
        },
      },
    });
    expect(rules['custom']?.confidence_threshold).toBe(0.5);
    expect(rules['custom']?.patterns).toEqual(['evilPattern']);
  });

  it('rejects non-object input', () => {
    expect(() => parseRulesObject([])).toThrow('Rules must be a JSON object');
  });
});

describe('normalizeRules', () => {
  it('fills default confidence_threshold', () => {
    const rules = normalizeRules({
      x: { patterns: ['a'], severity: 'LOW', description: 'd' },
    });
    expect(rules['x']?.confidence_threshold).toBe(0.5);
  });
});

describe('unsafeRegexReason', () => {
  it('accepts every built-in pattern', () => {
    for (const rule of Object.values(ENHANCED_RULES)) {
      for (const pattern of rule.patterns) {
        expect(unsafeRegexReason(pattern)).toBeUndefined();
      }
    }
  });

  it.each(['(a+)+$', '(\\w*)*x', '(.*)+y', '(?:[a-z]+)*'])('rejects nested quantifier %s', (p) => {
    expect(unsafeRegexReason(p)).toMatch(/nested quantifier/);
  });

  it.each(['(a|a)+', '(a|aa)+', '(\\w|\\d)+'])('rejects overlapping alternation %s', (p) => {
    expect(unsafeRegexReason(p)).toMatch(/overlapping/);
  });

  it('rejects a bounded span over 2000', () => {
    expect(unsafeRegexReason('x[\\s\\S]{0,5000}y')).toMatch(/too large/);
  });

  it('accepts fixed-width bodies under a quantifier', () => {
    expect(unsafeRegexReason('(?:\\\\x[0-9a-f]{2}){3,}')).toBeUndefined();
    expect(unsafeRegexReason('(foo|bar)+')).toBeUndefined();
  });
});

describe('compileRules', () => {
  const rules: EnhancedRules = {
    ok: { patterns: ['foo', 'bar'], severity: 'LOW', description: 'ok', confidence_threshold: 0.5 },
    bad: {
      patterns: ['(a+)+$', 'baz'],
      severity: 'LOW',
      description: 'bad',
      confidence_threshold: 0.5,
    },
  };

  it('compiles once per rules object and caches', () => {
    const a = compileRules(rules);
    const b = compileRules(rules);
    expect(a).toBe(b);
  });

  it('drops unsafe patterns and keeps the rest of the rule', () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      const compiled = compileRules({ ...rules });
      const bad = compiled.find((r) => r.name === 'bad');
      expect(bad?.patterns.map((p) => p.source)).toEqual(['baz']);
      expect(warn).toHaveBeenCalledWith(expect.stringContaining('unsafe regex'));
    } finally {
      warn.mockRestore();
    }
  });

  it('validateRules reports unsafe patterns as errors', () => {
    const { valid, errors } = validateRules(rules);
    expect(valid).toBe(false);
    expect(errors.some((e) => e.includes('unsafe regex'))).toBe(true);
  });
});

describe('applyRules budget and reuse', () => {
  const rules: EnhancedRules = {
    first: { patterns: ['alpha'], severity: 'LOW', description: 'a', confidence_threshold: 0.5 },
    second: { patterns: ['beta'], severity: 'LOW', description: 'b', confidence_threshold: 0.5 },
  };

  it('counts matches correctly on repeated calls (no shared lastIndex)', () => {
    const content = 'alpha alpha alpha';
    const r1 = applyRules(content, 'a.js', rules);
    const r2 = applyRules(content, 'a.js', rules);
    expect(r1.find((t) => t.rule === 'first')?.matches).toBe(3);
    expect(r2.find((t) => t.rule === 'first')?.matches).toBe(3);
  });

  it('emits RULE_TIMEOUT and stops when the budget is exhausted', () => {
    const out = applyRules('alpha beta', 'a.js', rules, -1);
    expect(out.map((t) => t.type)).toEqual(['RULE_TIMEOUT']);
    expect(out[0]?.severity).toBe('LOW');
  });
});
