const { checkGpgSignatures } = require('../../scan');

describe('GPG Signature Verification', () => {
  const mockOptions = { verbose: false };

  describe('checkGpgSignatures', () => {
    it('should detect missing GPG signatures', async () => {
      const packageData = {
        name: 'test-package',
        version: '1.0.0',
        dist: {
          tarball: 'https://registry.npmjs.org/test-package/-/test-package-1.0.0.tgz'
        }
      };

      const threats = await checkGpgSignatures(packageData, 'test-package', mockOptions);
      
      expect(threats.length).toBeGreaterThan(0);
      expect(threats[0].type).toBe('MISSING_GPG_SIGNATURE');
      expect(threats[0].severity).toBe('MEDIUM');
    });

    it('should detect invalid GPG signatures', async () => {
      const packageData = {
        name: 'test-package',
        version: '1.0.0',
        signatures: [
          {
            type: 'gpg',
            keyid: 'ABC12345',
            valid: false
          }
        ]
      };

      const threats = await checkGpgSignatures(packageData, 'test-package', mockOptions);
      
      expect(threats.length).toBeGreaterThan(0);
      expect(threats[0].type).toBe('INVALID_GPG_SIGNATURE');
      expect(threats[0].severity).toBe('HIGH');
    });

    it('should detect suspicious GPG keys', async () => {
      const packageData = {
        name: 'test-package',
        version: '1.0.0',
        signatures: [
          {
            type: 'gpg',
            keyid: '123', // Suspiciously short key
            valid: true
          }
        ]
      };

      const threats = await checkGpgSignatures(packageData, 'test-package', mockOptions);
      
      expect(threats.length).toBeGreaterThan(0);
      expect(threats[0].type).toBe('SUSPICIOUS_GPG_KEY');
      expect(threats[0].severity).toBe('MEDIUM');
    });

    it('should not flag valid GPG signatures', async () => {
      const packageData = {
        name: 'test-package',
        version: '1.0.0',
        signatures: [
          {
            type: 'gpg',
            keyid: 'ABCDEF1234567890',
            valid: true
          }
        ],
        dist: {
          tarball: 'https://registry.npmjs.org/test-package/-/test-package-1.0.0.tgz'
        }
      };

      const threats = await checkGpgSignatures(packageData, 'test-package', mockOptions);
      
      // Should not have any threats for valid signatures
      expect(threats.length).toBe(0);
    });

    it('should handle packages with no signatures field', async () => {
      const packageData = {
        name: 'test-package',
        version: '1.0.0',
        _hasShrinkwrap: false
      };

      const threats = await checkGpgSignatures(packageData, 'test-package', mockOptions);
      
      expect(threats.length).toBeGreaterThan(0);
      expect(threats[0].type).toBe('MISSING_GPG_SIGNATURE');
    });

    it('should check for GPG signature files in tarball', async () => {
      const packageData = {
        name: 'test-package',
        version: '1.0.0',
        dist: {
          tarball: 'https://registry.npmjs.org/test-package/-/test-package-1.0.0.tgz'
        }
      };

      const threats = await checkGpgSignatures(packageData, 'test-package', mockOptions);
      
      // Should detect missing GPG signature file
      const missingSignatureThreat = threats.find(t => 
        t.type === 'MISSING_GPG_SIGNATURE' && 
        t.details.includes('tarball does not have accompanying GPG signature file')
      );
      expect(missingSignatureThreat).toBeDefined();
    });

    it('should handle empty package data gracefully', async () => {
      const threats = await checkGpgSignatures(null, 'test-package', mockOptions);
      
      expect(threats.length).toBe(0);
    });

    it('should handle packages with PGP signatures', async () => {
      const packageData = {
        name: 'test-package',
        version: '1.0.0',
        signatures: [
          {
            type: 'pgp',
            keyid: 'ABCDEF1234567890',
            valid: true
          }
        ]
      };

      const threats = await checkGpgSignatures(packageData, 'test-package', mockOptions);
      
      // Should not flag valid PGP signatures
      expect(threats.length).toBe(0);
    });

    it('should detect multiple invalid signatures', async () => {
      const packageData = {
        name: 'test-package',
        version: '1.0.0',
        signatures: [
          {
            type: 'gpg',
            keyid: 'ABC12345',
            valid: false
          },
          {
            type: 'gpg',
            keyid: 'DEF67890',
            valid: false
          }
        ]
      };

      const threats = await checkGpgSignatures(packageData, 'test-package', mockOptions);
      
      expect(threats.length).toBe(2);
      expect(threats.every(t => t.type === 'INVALID_GPG_SIGNATURE')).toBe(true);
    });

    it('should handle mixed valid and invalid signatures', async () => {
      const packageData = {
        name: 'test-package',
        version: '1.0.0',
        signatures: [
          {
            type: 'gpg',
            keyid: 'ABCDEF1234567890',
            valid: true
          },
          {
            type: 'gpg',
            keyid: 'INVALID123',
            valid: false
          }
        ]
      };

      const threats = await checkGpgSignatures(packageData, 'test-package', mockOptions);
      
      expect(threats.length).toBe(1);
      expect(threats[0].type).toBe('INVALID_GPG_SIGNATURE');
    });
  });
});
