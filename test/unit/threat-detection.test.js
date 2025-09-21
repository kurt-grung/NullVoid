const { describe, it, expect, beforeEach, afterEach } = require('@jest/globals');
const { checkObfuscatedIoCs, detectCircularDependencies } = require('../../scan');

describe('Threat Detection', () => {
  describe('checkObfuscatedIoCs', () => {
    it('should detect known obfuscated patterns', () => {
      const maliciousContent = 'var _0x112fa8 = "malicious"; var _0x180f = "code";';
      const threats = checkObfuscatedIoCs(maliciousContent, 'test-package');
      
      expect(threats.length).toBeGreaterThan(0);
      expect(threats[0].type).toBe('OBFUSCATED_IOC');
      expect(threats[0].severity).toBe('CRITICAL');
    });

    it('should not detect threats in clean content', () => {
      const cleanContent = 'function hello() { return "world"; }';
      const threats = checkObfuscatedIoCs(cleanContent, 'test-package');
      
      expect(threats).toEqual([]);
    });

    it('should detect multiple obfuscated patterns', () => {
      const maliciousContent = '_0x112fa8 _0x180f _0x20669a';
      const threats = checkObfuscatedIoCs(maliciousContent, 'test-package');
      
      expect(threats.length).toBeGreaterThan(1);
      threats.forEach(threat => {
        expect(threat.type).toBe('OBFUSCATED_IOC');
        expect(threat.severity).toBe('CRITICAL');
      });
    });

    it('should include package name in threat details', () => {
      const maliciousContent = '_0x112fa8';
      const threats = checkObfuscatedIoCs(maliciousContent, 'test-package');
      
      expect(threats[0].package).toBe('test-package');
    });
  });

  describe('detectCircularDependencies', () => {
    it('should detect circular dependencies', () => {
      const tree = {
        'package-a': {
          dependencies: {
            'package-b': '1.0.0'
          }
        },
        'package-b': {
          dependencies: {
            'package-a': '1.0.0'
          }
        }
      };
      
      const circular = detectCircularDependencies(tree);
      
      expect(circular.length).toBeGreaterThan(0);
      expect(circular[0]).toContain('package-a');
      expect(circular[0]).toContain('package-b');
    });

    it('should not detect circular dependencies in clean tree', () => {
      const tree = {
        'package-a': {
          dependencies: {
            'package-b': '1.0.0'
          }
        },
        'package-b': {
          dependencies: {}
        }
      };
      
      const circular = detectCircularDependencies(tree);
      
      expect(circular).toEqual([]);
    });

    it('should handle complex circular dependencies', () => {
      const tree = {
        'package-a': {
          dependencies: {
            'package-b': '1.0.0'
          }
        },
        'package-b': {
          dependencies: {
            'package-c': '1.0.0'
          }
        },
        'package-c': {
          dependencies: {
            'package-a': '1.0.0'
          }
        }
      };
      
      const circular = detectCircularDependencies(tree);
      
      expect(circular.length).toBeGreaterThan(0);
    });

    it('should handle empty tree', () => {
      const tree = {};
      const circular = detectCircularDependencies(tree);
      
      expect(circular).toEqual([]);
    });
  });
});

