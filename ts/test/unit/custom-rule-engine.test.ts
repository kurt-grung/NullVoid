import { describe, it, expect } from '@jest/globals';
import { runCustomRuleEngine } from '../../src/lib/customRuleEngine';

describe('customRuleEngine', () => {
  it('matches enhanced wallet hijacking patterns', () => {
    const content = 'window.ethereum = new Proxy(window.ethereum, {})';
    const threats = runCustomRuleEngine(content, 'pkg/index.js');
    expect(threats.length).toBeGreaterThan(0);
    expect(threats[0]?.type).toContain('WALLET_HIJACKING');
  });
});
