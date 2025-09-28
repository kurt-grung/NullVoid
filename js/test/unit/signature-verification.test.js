const { describe, it, expect, beforeEach, afterEach } = require('@jest/globals');
const {
  checkPackageSignatures,
  checkPackageIntegrity,
  checkTarballSignatures,
  checkPackageJsonSignatures,
  checkMaintainerSignatures
} = require('../../scan');

describe('Signature Verification', () => {
  describe('checkPackageIntegrity', () => {
    it('should detect malformed integrity hash', async () => {
      const packageData = {
        name: 'test-package',
        version: '1.0.0',
        integrity: 'invalid-hash-format'
      };
      
      const threats = await checkPackageIntegrity(packageData, 'test-package');
      
      expect(threats).toHaveLength(1);
      expect(threats[0].type).toBe('SUSPICIOUS_INTEGRITY');
      expect(threats[0].severity).toBe('HIGH');
    });

    it('should detect missing integrity hash', async () => {
      const packageData = {
        name: 'test-package',
        version: '1.0.0'
        // No integrity field
      };
      
      const threats = await checkPackageIntegrity(packageData, 'test-package');
      
      expect(threats).toHaveLength(1);
      expect(threats[0].type).toBe('MISSING_INTEGRITY');
      expect(threats[0].severity).toBe('MEDIUM');
    });

    it('should detect suspicious rapid version releases', async () => {
      const now = new Date();
      const thirtyMinutesAgo = new Date(now.getTime() - 30 * 60 * 1000); // 30 minutes ago
      
      const packageData = {
        name: 'test-package',
        version: '1.0.1',
        integrity: 'sha512-validhash',
        time: {
          '1.0.0': thirtyMinutesAgo.toISOString(),
          '1.0.1': now.toISOString(),
          created: '2023-01-01T00:00:00.000Z',
          modified: now.toISOString()
        }
      };
      
      const threats = await checkPackageIntegrity(packageData, 'test-package');
      
      expect(threats).toHaveLength(1);
      expect(threats[0].type).toBe('SUSPICIOUS_VERSION_PATTERN');
      expect(threats[0].severity).toBe('HIGH');
    });

    it('should not flag valid integrity hash', async () => {
      const packageData = {
        name: 'test-package',
        version: '1.0.0',
        integrity: 'sha512-abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890=='
      };
      
      const threats = await checkPackageIntegrity(packageData, 'test-package');
      
      expect(threats).toHaveLength(0);
    });
  });

  describe('checkPackageJsonSignatures', () => {
    it('should detect suspicious content in package.json', async () => {
      const packageData = {
        name: 'test-package',
        version: '1.0.0',
        description: 'eval("malicious code")'
      };
      
      const threats = await checkPackageJsonSignatures(packageData, 'test-package');
      
      expect(threats).toHaveLength(1);
      expect(threats[0].type).toBe('SUSPICIOUS_PACKAGE_JSON_CONTENT');
      expect(threats[0].severity).toBe('MEDIUM');
    });

    it('should detect missing essential fields', async () => {
      const packageData = {
        version: '1.0.0'
        // Missing name and description
      };
      
      const threats = await checkPackageJsonSignatures(packageData, 'test-package');
      
      expect(threats).toHaveLength(2);
      expect(threats[0].type).toBe('MISSING_ESSENTIAL_FIELD');
      expect(threats[1].type).toBe('MISSING_ESSENTIAL_FIELD');
    });

    it('should detect suspiciously high version numbers', async () => {
      const packageData = {
        name: 'test-package',
        version: '999.0.0',
        description: 'Test package'
      };
      
      const threats = await checkPackageJsonSignatures(packageData, 'test-package');
      
      expect(threats).toHaveLength(1);
      expect(threats[0].type).toBe('SUSPICIOUS_VERSION_NUMBER');
      expect(threats[0].severity).toBe('MEDIUM');
    });

    it('should not flag normal package.json', async () => {
      const packageData = {
        name: 'test-package',
        version: '1.0.0',
        description: 'A normal test package'
      };
      
      const threats = await checkPackageJsonSignatures(packageData, 'test-package');
      
      expect(threats).toHaveLength(0);
    });
  });

  describe('checkMaintainerSignatures', () => {
    it('should detect suspicious maintainer email', async () => {
      const packageData = {
        name: 'test-package',
        version: '1.0.0',
        maintainers: [
          {
            name: 'Test User',
            email: 'test@temp-mail.com'
          }
        ]
      };
      
      const threats = await checkMaintainerSignatures(packageData, 'test-package');
      
      expect(threats.length).toBeGreaterThan(0);
      expect(threats.some(t => t.type === 'SUSPICIOUS_MAINTAINER')).toBe(true);
    });

    it('should detect incomplete maintainer information', async () => {
      const packageData = {
        name: 'test-package',
        version: '1.0.0',
        maintainers: [
          {
            // Missing both name and email
          }
        ]
      };
      
      const threats = await checkMaintainerSignatures(packageData, 'test-package');
      
      expect(threats).toHaveLength(1);
      expect(threats[0].type).toBe('INCOMPLETE_MAINTAINER_INFO');
      expect(threats[0].severity).toBe('LOW');
    });

    it('should detect recent maintainer changes', async () => {
      const now = new Date();
      const threeDaysAgo = new Date(now.getTime() - 3 * 24 * 60 * 60 * 1000);
      
      const packageData = {
        name: 'test-package',
        version: '1.0.0',
        time: {
          modified: threeDaysAgo.toISOString()
        }
      };
      
      const threats = await checkMaintainerSignatures(packageData, 'test-package');
      
      expect(threats).toHaveLength(1);
      expect(threats[0].type).toBe('RECENT_MAINTAINER_CHANGE');
      expect(threats[0].severity).toBe('MEDIUM');
    });

    it('should not flag normal maintainer information', async () => {
      const packageData = {
        name: 'test-package',
        version: '1.0.0',
        maintainers: [
          {
            name: 'John Doe',
            email: 'john@company.com'
          }
        ]
      };
      
      const threats = await checkMaintainerSignatures(packageData, 'test-package');
      
      expect(threats).toHaveLength(0);
    });
  });

  describe('checkPackageSignatures', () => {
    it('should run all signature checks', async () => {
      const packageData = {
        name: 'test-package',
        version: '1.0.0',
        integrity: 'invalid-hash',
        maintainers: [
          {
            email: 'test@temp-mail.com'
          }
        ]
      };
      
      const options = { verbose: false };
      const threats = await checkPackageSignatures(packageData, 'test-package', options);
      
      // Should have threats from multiple checks
      expect(threats.length).toBeGreaterThan(0);
      
      const threatTypes = threats.map(t => t.type);
      expect(threatTypes).toContain('SUSPICIOUS_INTEGRITY');
      expect(threatTypes).toContain('SUSPICIOUS_MAINTAINER');
    });

    it('should handle empty package data', async () => {
      const threats = await checkPackageSignatures(null, 'test-package', {});
      
      expect(threats).toHaveLength(0);
    });
  });
});
