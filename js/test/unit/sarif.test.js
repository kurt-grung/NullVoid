/**
 * Unit tests for SARIF output generation
 */

const { generateSarifOutput, validateSarifOutput, RULE_DEFINITIONS } = require('../../lib/sarif');

describe('SARIF Output Generation', () => {
  const mockResults = {
    threats: [
      {
        type: 'WALLET_HIJACKING',
        message: 'Package may contain wallet hijacking code',
        severity: 'CRITICAL',
        package: '📁 /path/to/suspicious-package/index.js',
        lineNumber: 42,
        sampleCode: 'window.ethereum = new Proxy(...)',
        details: 'Detected Ethereum wallet interception'
      },
      {
        type: 'HIGH_ENTROPY',
        message: 'Package contains high entropy code',
        severity: 'MEDIUM',
        package: '📦 npm-registry://obfuscated-lib@latest',
        lineNumber: 15,
        details: 'Entropy value: 6.8'
      }
    ],
    packagesScanned: 2,
    filesScanned: 5,
    duration: 1500
  };

  const mockOptions = {
    maxDepth: 3,
    all: false,
    verbose: true,
    parallel: true
  };

  describe('generateSarifOutput', () => {
    test('should generate valid SARIF structure', () => {
      const sarif = generateSarifOutput(mockResults, mockOptions);

      expect(sarif).toHaveProperty('$schema');
      expect(sarif).toHaveProperty('version', '2.1.0');
      expect(sarif).toHaveProperty('runs');
      expect(Array.isArray(sarif.runs)).toBe(true);
      expect(sarif.runs).toHaveLength(1);
    });

    test('should include tool information', () => {
      const sarif = generateSarifOutput(mockResults, mockOptions);
      const run = sarif.runs[0];

      expect(run.tool).toHaveProperty('driver');
      expect(run.tool.driver).toHaveProperty('name', 'NullVoid');
      expect(run.tool.driver).toHaveProperty('version');
      expect(run.tool.driver).toHaveProperty('informationUri');
      expect(run.tool.driver).toHaveProperty('fullName');
      expect(run.tool.driver).toHaveProperty('shortDescription');
      expect(run.tool.driver).toHaveProperty('fullDescription');
    });

    test('should include rule definitions for detected threats', () => {
      const sarif = generateSarifOutput(mockResults, mockOptions);
      const run = sarif.runs[0];

      expect(run.tool.driver).toHaveProperty('rules');
      expect(Array.isArray(run.tool.driver.rules)).toBe(true);
      expect(run.tool.driver.rules.length).toBeGreaterThan(0);

      // Check that rules include detected threat types
      const ruleIds = run.tool.driver.rules.map(rule => rule.id);
      expect(ruleIds).toContain('WALLET_HIJACKING');
      expect(ruleIds).toContain('HIGH_ENTROPY');
    });

    test('should include invocation information', () => {
      const sarif = generateSarifOutput(mockResults, mockOptions);
      const run = sarif.runs[0];

      expect(run).toHaveProperty('invocations');
      expect(Array.isArray(run.invocations)).toBe(true);
      expect(run.invocations).toHaveLength(1);

      const invocation = run.invocations[0];
      expect(invocation).toHaveProperty('executionSuccessful', true);
      expect(invocation).toHaveProperty('exitCode');
      expect(invocation).toHaveProperty('exitCodeDescription');
      expect(invocation).toHaveProperty('startTimeUtc');
      expect(invocation).toHaveProperty('endTimeUtc');
    });

    test('should include scan results', () => {
      const sarif = generateSarifOutput(mockResults, mockOptions);
      const run = sarif.runs[0];

      expect(run).toHaveProperty('results');
      expect(Array.isArray(run.results)).toBe(true);
      expect(run.results).toHaveLength(1); // Only CRITICAL threat (HIGH/CRITICAL filter)
    });

    test('should include scan properties and metrics', () => {
      const sarif = generateSarifOutput(mockResults, mockOptions);
      const run = sarif.runs[0];

      expect(run).toHaveProperty('properties');
      expect(run.properties).toHaveProperty('scanOptions');
      expect(run.properties).toHaveProperty('scanMetrics');

      expect(run.properties.scanOptions).toHaveProperty('maxDepth', 3);
      expect(run.properties.scanOptions).toHaveProperty('showAll', false);
      expect(run.properties.scanOptions).toHaveProperty('verbose', true);
      expect(run.properties.scanOptions).toHaveProperty('parallel', true);

      expect(run.properties.scanMetrics).toHaveProperty('packagesScanned', 2);
      expect(run.properties.scanMetrics).toHaveProperty('filesScanned', 5);
      expect(run.properties.scanMetrics).toHaveProperty('duration', 1500);
      expect(run.properties.scanMetrics).toHaveProperty('threatsDetected', 2);
    });

    test('should filter results based on options.all', () => {
      const optionsWithAll = { ...mockOptions, all: true };
      const sarifWithAll = generateSarifOutput(mockResults, optionsWithAll);
      
      const optionsWithoutAll = { ...mockOptions, all: false };
      const sarifWithoutAll = generateSarifOutput(mockResults, optionsWithoutAll);

      // With all=true, should include all threats
      expect(sarifWithAll.runs[0].results).toHaveLength(2);
      
      // With all=false, should only include HIGH/CRITICAL threats
      expect(sarifWithoutAll.runs[0].results).toHaveLength(1); // Only CRITICAL threat
    });

    test('should handle empty results', () => {
      const emptyResults = {
        threats: [],
        packagesScanned: 0,
        filesScanned: 0,
        duration: 100
      };

      const sarif = generateSarifOutput(emptyResults, mockOptions);

      expect(sarif.runs[0].results).toHaveLength(0);
      expect(sarif.runs[0].tool.driver.rules).toHaveLength(0);
      expect(sarif.runs[0].invocations[0].exitCode).toBe(0);
      expect(sarif.runs[0].invocations[0].exitCodeDescription).toBe('No threats detected');
    });
  });

  describe('SARIF Results Structure', () => {
    test('should generate valid result objects', () => {
      const sarif = generateSarifOutput(mockResults, mockOptions);
      const results = sarif.runs[0].results;

      results.forEach(result => {
        expect(result).toHaveProperty('ruleId');
        expect(result).toHaveProperty('level');
        expect(result).toHaveProperty('message');
        expect(result).toHaveProperty('locations');
        expect(result).toHaveProperty('properties');

        expect(result.message).toHaveProperty('text');
        expect(Array.isArray(result.locations)).toBe(true);
        expect(result.properties).toHaveProperty('severity');
        expect(result.properties).toHaveProperty('confidence', 'high');
      });
    });

    test('should map severity levels correctly', () => {
      const optionsWithAll = { ...mockOptions, all: true };
      const sarif = generateSarifOutput(mockResults, optionsWithAll);
      const results = sarif.runs[0].results;

      const criticalResult = results.find(r => r.ruleId === 'WALLET_HIJACKING');
      expect(criticalResult.level).toBe('error');

      const mediumResult = results.find(r => r.ruleId === 'HIGH_ENTROPY');
      expect(mediumResult.level).toBe('warning');
    });

    test('should include location information', () => {
      const sarif = generateSarifOutput(mockResults, mockOptions);
      const results = sarif.runs[0].results;

      results.forEach(result => {
        expect(result.locations).toHaveLength(1);
        const location = result.locations[0];
        
        expect(location).toHaveProperty('physicalLocation');
        expect(location.physicalLocation).toHaveProperty('artifactLocation');
        expect(location.physicalLocation.artifactLocation).toHaveProperty('uri');
      });
    });

    test('should clean package paths', () => {
      const sarif = generateSarifOutput(mockResults, mockOptions);
      const results = sarif.runs[0].results;

      const walletResult = results.find(r => r.ruleId === 'WALLET_HIJACKING');
      const uri = walletResult.locations[0].physicalLocation.artifactLocation.uri;
      
      // Should remove emoji and color codes
      expect(uri).not.toContain('📁');
      expect(uri).not.toContain('📦');
      expect(uri).not.toContain('\x1b[');
    });

    test('should include line number information when available', () => {
      const sarif = generateSarifOutput(mockResults, mockOptions);
      const results = sarif.runs[0].results;

      const walletResult = results.find(r => r.ruleId === 'WALLET_HIJACKING');
      const region = walletResult.locations[0].physicalLocation.region;
      
      expect(region).toHaveProperty('startLine', 42);
      expect(region).toHaveProperty('startColumn', 1);
    });

    test('should include additional properties', () => {
      const sarif = generateSarifOutput(mockResults, mockOptions);
      const results = sarif.runs[0].results;

      const walletResult = results.find(r => r.ruleId === 'WALLET_HIJACKING');
      expect(walletResult.properties).toHaveProperty('sampleCode');
      expect(walletResult.properties).toHaveProperty('details');
      expect(walletResult.properties).toHaveProperty('lineNumber');
    });
  });

  describe('validateSarifOutput', () => {
    test('should validate correct SARIF structure', () => {
      const sarif = generateSarifOutput(mockResults, mockOptions);
      const validation = validateSarifOutput(sarif);

      expect(validation.valid).toBe(true);
      expect(validation.errors).toHaveLength(0);
    });

    test('should detect missing schema', () => {
      const invalidSarif = { version: '2.1.0' };
      const validation = validateSarifOutput(invalidSarif);

      expect(validation.valid).toBe(false);
      expect(validation.errors).toContain('Missing $schema property');
    });

    test('should detect missing version', () => {
      const invalidSarif = { $schema: 'test' };
      const validation = validateSarifOutput(invalidSarif);

      expect(validation.valid).toBe(false);
      expect(validation.errors).toContain('Missing version property');
    });

    test('should detect missing runs array', () => {
      const invalidSarif = { $schema: 'test', version: '2.1.0' };
      const validation = validateSarifOutput(invalidSarif);

      expect(validation.valid).toBe(false);
      expect(validation.errors).toContain('Missing or invalid runs array');
    });

    test('should detect missing tool driver', () => {
      const invalidSarif = {
        $schema: 'test',
        version: '2.1.0',
        runs: [{}]
      };
      const validation = validateSarifOutput(invalidSarif);

      expect(validation.valid).toBe(false);
      expect(validation.errors).toContain('Missing tool driver information');
    });

    test('should detect missing results array', () => {
      const invalidSarif = {
        $schema: 'test',
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'test' } }
        }]
      };
      const validation = validateSarifOutput(invalidSarif);

      expect(validation.valid).toBe(false);
      expect(validation.errors).toContain('Missing or invalid results array');
    });

    test('should generate warnings for incomplete results', () => {
      const invalidSarif = {
        $schema: 'test',
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'test' } },
          results: [
            { ruleId: 'test' }, // Missing message
            { message: { text: 'test' } } // Missing ruleId
          ]
        }]
      };
      const validation = validateSarifOutput(invalidSarif);

      expect(validation.valid).toBe(true); // Structure is valid
      expect(validation.warnings.length).toBeGreaterThan(0);
      expect(validation.warnings.some(w => w.includes('Missing message text'))).toBe(true);
      expect(validation.warnings.some(w => w.includes('Missing ruleId'))).toBe(true);
    });
  });

  describe('RULE_DEFINITIONS', () => {
    test('should include all expected rule definitions', () => {
      const expectedRules = [
        'WALLET_HIJACKING',
        'NETWORK_MANIPULATION',
        'HIGH_ENTROPY',
        'SUSPICIOUS_SCRIPTS',
        'MULTI_CHAIN_TARGETING',
        'STEALTH_CONTROLS',
        'OBFUSCATED_CODE',
        'SUSPICIOUS_PATTERNS',
        'SIGNATURE_ISSUES',
        'DYNAMIC_REQUIRES'
      ];

      expectedRules.forEach(ruleId => {
        expect(RULE_DEFINITIONS).toHaveProperty(ruleId);
        const rule = RULE_DEFINITIONS[ruleId];
        
        expect(rule).toHaveProperty('id', ruleId);
        expect(rule).toHaveProperty('name');
        expect(rule).toHaveProperty('shortDescription');
        expect(rule).toHaveProperty('fullDescription');
        expect(rule).toHaveProperty('help');
        expect(rule).toHaveProperty('helpUri');
        expect(rule).toHaveProperty('properties');
        
        expect(rule.shortDescription).toHaveProperty('text');
        expect(rule.fullDescription).toHaveProperty('text');
        expect(rule.help).toHaveProperty('text');
        expect(rule.properties).toHaveProperty('tags');
        expect(rule.properties).toHaveProperty('precision');
        expect(rule.properties).toHaveProperty('severity');
      });
    });

    test('should have valid help URIs', () => {
      Object.values(RULE_DEFINITIONS).forEach(rule => {
        expect(rule.helpUri).toMatch(/^https:\/\/github\.com\/kurt-grung\/NullVoid#/);
      });
    });

    test('should have appropriate severity levels', () => {
      Object.values(RULE_DEFINITIONS).forEach(rule => {
        expect(['error', 'warning', 'note']).toContain(rule.properties.severity);
      });
    });

    test('should have appropriate precision levels', () => {
      Object.values(RULE_DEFINITIONS).forEach(rule => {
        expect(['high', 'medium', 'low']).toContain(rule.properties.precision);
      });
    });
  });
});
