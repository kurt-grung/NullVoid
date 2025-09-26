/**
 * SARIF Output Generator for NullVoid
 * Generates SARIF (Static Analysis Results Interchange Format) output for CI/CD integration
 */

const path = require('path');
const packageJson = require('../package.json');

/**
 * SARIF severity mapping from NullVoid severity levels
 */
const SEVERITY_MAPPING = {
  'CRITICAL': 'error',
  'HIGH': 'error', 
  'MEDIUM': 'warning',
  'LOW': 'note',
  'INFO': 'note'
};

/**
 * SARIF level mapping from NullVoid severity levels
 */
const LEVEL_MAPPING = {
  'CRITICAL': 'error',
  'HIGH': 'error',
  'MEDIUM': 'warning', 
  'LOW': 'note',
  'INFO': 'note'
};

/**
 * Rule definitions for NullVoid threat types
 */
const RULE_DEFINITIONS = {
  'WALLET_HIJACKING': {
    id: 'WALLET_HIJACKING',
    name: 'Wallet Hijacking Detection',
    shortDescription: {
      text: 'Detects packages that may contain wallet hijacking code'
    },
    fullDescription: {
      text: 'Identifies packages that attempt to intercept or manipulate cryptocurrency wallet operations, including Ethereum, MetaMask, and other blockchain wallet interactions.'
    },
    help: {
      text: 'This package may contain code that intercepts wallet operations. Review the package source code and consider removing it if not essential.'
    },
    helpUri: 'https://github.com/kurt-grung/NullVoid#wallet-hijacking-detection',
    properties: {
      tags: ['security', 'wallet', 'cryptocurrency', 'blockchain'],
      precision: 'high',
      severity: 'error'
    }
  },
  'NETWORK_MANIPULATION': {
    id: 'NETWORK_MANIPULATION',
    name: 'Network Manipulation Detection',
    shortDescription: {
      text: 'Detects packages that may manipulate network responses'
    },
    fullDescription: {
      text: 'Identifies packages that override or intercept network requests and responses, potentially for data exfiltration or address replacement attacks.'
    },
    help: {
      text: 'This package may manipulate network traffic. Review network-related code and consider the security implications.'
    },
    helpUri: 'https://github.com/kurt-grung/NullVoid#network-manipulation-detection',
    properties: {
      tags: ['security', 'network', 'interception'],
      precision: 'high',
      severity: 'error'
    }
  },
  'HIGH_ENTROPY': {
    id: 'HIGH_ENTROPY',
    name: 'High Entropy Code Detection',
    shortDescription: {
      text: 'Detects packages with unusually high entropy (obfuscated code)'
    },
    fullDescription: {
      text: 'Identifies packages containing code with high entropy values, which may indicate obfuscation, packing, or other code hiding techniques commonly used in malware.'
    },
    help: {
      text: 'This package contains high-entropy code that may be obfuscated. Review the code for legitimacy and consider the security implications.'
    },
    helpUri: 'https://github.com/kurt-grung/NullVoid#entropy-analysis',
    properties: {
      tags: ['security', 'obfuscation', 'entropy'],
      precision: 'medium',
      severity: 'warning'
    }
  },
  'SUSPICIOUS_SCRIPTS': {
    id: 'SUSPICIOUS_SCRIPTS',
    name: 'Suspicious Scripts Detection',
    shortDescription: {
      text: 'Detects suspicious postinstall or build scripts'
    },
    fullDescription: {
      text: 'Identifies packages with suspicious postinstall scripts or build processes that may execute malicious code during package installation.'
    },
    help: {
      text: 'This package contains suspicious scripts. Review the postinstall and build scripts for potential security risks.'
    },
    helpUri: 'https://github.com/kurt-grung/NullVoid#postinstall-script-analysis',
    properties: {
      tags: ['security', 'scripts', 'postinstall'],
      precision: 'high',
      severity: 'error'
    }
  },
  'MULTI_CHAIN_TARGETING': {
    id: 'MULTI_CHAIN_TARGETING',
    name: 'Multi-Chain Targeting Detection',
    shortDescription: {
      text: 'Detects packages targeting multiple blockchain networks'
    },
    fullDescription: {
      text: 'Identifies packages that contain code targeting multiple cryptocurrency networks, which may indicate sophisticated wallet hijacking attacks.'
    },
    help: {
      text: 'This package targets multiple blockchain networks. Review for potential wallet hijacking or cryptocurrency-related attacks.'
    },
    helpUri: 'https://github.com/kurt-grung/NullVoid#multi-chain-targeting',
    properties: {
      tags: ['security', 'blockchain', 'multi-chain'],
      precision: 'medium',
      severity: 'warning'
    }
  },
  'STEALTH_CONTROLS': {
    id: 'STEALTH_CONTROLS',
    name: 'Stealth Controls Detection',
    shortDescription: {
      text: 'Detects stealth controls and obfuscation techniques'
    },
    fullDescription: {
      text: 'Identifies packages containing stealth controls, anti-analysis techniques, or other obfuscation methods commonly used in malware.'
    },
    help: {
      text: 'This package contains stealth controls or obfuscation. Review the code for potential malicious behavior.'
    },
    helpUri: 'https://github.com/kurt-grung/NullVoid#stealth-controls',
    properties: {
      tags: ['security', 'stealth', 'obfuscation'],
      precision: 'high',
      severity: 'error'
    }
  },
  'OBFUSCATED_CODE': {
    id: 'OBFUSCATED_CODE',
    name: 'Obfuscated Code Detection',
    shortDescription: {
      text: 'Detects obfuscated or packed code'
    },
    fullDescription: {
      text: 'Identifies packages containing obfuscated code patterns, variable name mangling, or other code hiding techniques.'
    },
    help: {
      text: 'This package contains obfuscated code. Review for potential security risks and consider the necessity of obfuscation.'
    },
    helpUri: 'https://github.com/kurt-grung/NullVoid#obfuscation-detection',
    properties: {
      tags: ['security', 'obfuscation', 'code-hiding'],
      precision: 'medium',
      severity: 'warning'
    }
  },
  'SUSPICIOUS_PATTERNS': {
    id: 'SUSPICIOUS_PATTERNS',
    name: 'Suspicious Patterns Detection',
    shortDescription: {
      text: 'Detects suspicious file patterns and naming conventions'
    },
    fullDescription: {
      text: 'Identifies packages with suspicious file patterns, naming conventions, or structural elements that may indicate malicious intent.'
    },
    help: {
      text: 'This package contains suspicious patterns. Review the file structure and naming conventions for potential security risks.'
    },
    helpUri: 'https://github.com/kurt-grung/NullVoid#suspicious-patterns',
    properties: {
      tags: ['security', 'patterns', 'structure'],
      precision: 'medium',
      severity: 'warning'
    }
  },
  'SIGNATURE_ISSUES': {
    id: 'SIGNATURE_ISSUES',
    name: 'Signature Verification Issues',
    shortDescription: {
      text: 'Detects package signature verification problems'
    },
    fullDescription: {
      text: 'Identifies packages with signature verification issues, missing signatures, or suspicious signing patterns.'
    },
    help: {
      text: 'This package has signature verification issues. Review the package signatures and consider the security implications.'
    },
    helpUri: 'https://github.com/kurt-grung/NullVoid#signature-verification',
    properties: {
      tags: ['security', 'signature', 'verification'],
      precision: 'high',
      severity: 'warning'
    }
  },
  'DYNAMIC_REQUIRES': {
    id: 'DYNAMIC_REQUIRES',
    name: 'Dynamic Module Loading Detection',
    shortDescription: {
      text: 'Detects dynamic require() calls and module loading'
    },
    fullDescription: {
      text: 'Identifies packages that use dynamic require() calls or other dynamic module loading techniques that may be used for malicious purposes.'
    },
    help: {
      text: 'This package uses dynamic module loading. Review the dynamic require patterns for potential security risks.'
    },
    helpUri: 'https://github.com/kurt-grung/NullVoid#dynamic-requires',
    properties: {
      tags: ['security', 'dynamic', 'modules'],
      precision: 'medium',
      severity: 'warning'
    }
  }
};

/**
 * Generate SARIF output from NullVoid scan results
 * @param {Object} results - NullVoid scan results
 * @param {Object} options - Scan options
 * @returns {Object} SARIF format object
 */
function generateSarifOutput(results, options = {}) {
  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'NullVoid',
          version: packageJson.version,
          informationUri: 'https://github.com/kurt-grung/NullVoid',
          fullName: 'NullVoid Security Scanner',
          shortDescription: {
            text: 'Advanced static analysis security scanner for JavaScript/Node.js projects'
          },
          fullDescription: {
            text: 'NullVoid detects malicious code, supply chain attacks, wallet hijacking, obfuscated malware, and other security threats in JavaScript/Node.js projects and npm packages.'
          },
          rules: generateRuleDefinitions(results.threats || [])
        }
      },
      invocations: [{
        executionSuccessful: true,
        exitCode: results.threats && results.threats.length > 0 ? 1 : 0,
        exitCodeDescription: results.threats && results.threats.length > 0 ? 
          'Threats detected' : 'No threats detected',
        startTimeUtc: new Date().toISOString(),
        endTimeUtc: new Date().toISOString(),
        toolExecutionNotifications: []
      }],
      results: generateResults(results.threats || [], options),
      properties: {
        scanOptions: {
          maxDepth: options.maxDepth || 3,
          showAll: options.all || false,
          verbose: options.verbose || false,
          parallel: options.parallel !== false
        },
        scanMetrics: {
          packagesScanned: results.packagesScanned || 0,
          filesScanned: results.filesScanned || 0,
          duration: results.duration || 0,
          threatsDetected: results.threats ? results.threats.length : 0
        }
      }
    }]
  };

  return sarif;
}

/**
 * Generate rule definitions for detected threat types
 * @param {Array} threats - Array of detected threats
 * @returns {Array} Array of SARIF rule definitions
 */
function generateRuleDefinitions(threats) {
  const ruleIds = new Set();
  
  // Collect unique rule IDs from threats
  threats.forEach(threat => {
    if (threat.type && RULE_DEFINITIONS[threat.type]) {
      ruleIds.add(threat.type);
    }
  });

  // Generate rule definitions for detected threat types
  return Array.from(ruleIds).map(ruleId => RULE_DEFINITIONS[ruleId]);
}

/**
 * Generate SARIF results from threats
 * @param {Array} threats - Array of detected threats
 * @param {Object} options - Scan options
 * @returns {Array} Array of SARIF results
 */
function generateResults(threats, options = {}) {
  const results = [];
  
  // Filter threats based on options
  const filteredThreats = options.all ? threats : 
    threats.filter(threat => 
      threat.severity === 'CRITICAL' || threat.severity === 'HIGH'
    );

  filteredThreats.forEach((threat, index) => {
    const result = {
      ruleId: threat.type || 'UNKNOWN_THREAT',
      level: LEVEL_MAPPING[threat.severity] || 'note',
      message: {
        text: threat.message || 'Security threat detected'
      },
      locations: generateLocations(threat),
      properties: {
        threatIndex: index + 1,
        severity: threat.severity || 'MEDIUM',
        confidence: 'high'
      }
    };

    // Add additional properties if available
    if (threat.sampleCode) {
      result.properties.sampleCode = threat.sampleCode;
    }
    
    if (threat.details) {
      result.properties.details = threat.details;
    }

    if (threat.lineNumber) {
      result.properties.lineNumber = threat.lineNumber;
    }

    results.push(result);
  });

  return results;
}

/**
 * Generate SARIF locations from threat data
 * @param {Object} threat - Threat object
 * @returns {Array} Array of SARIF locations
 */
function generateLocations(threat) {
  const locations = [];

  if (threat.package) {
    // Clean up package path for SARIF
    let cleanPath = threat.package;
    
    // Remove emoji indicators
    cleanPath = cleanPath.replace(/📁\s*/, '').replace(/📦\s*/, '');
    
    // Remove color codes
    cleanPath = cleanPath.replace(/\x1b\[[0-9;]*m/g, '');
    
    // Convert to relative path if possible
    if (cleanPath.startsWith(process.cwd())) {
      cleanPath = path.relative(process.cwd(), cleanPath);
    }

    const location = {
      physicalLocation: {
        artifactLocation: {
          uri: cleanPath
        }
      }
    };

    // Add region information if line number is available
    if (threat.lineNumber) {
      location.physicalLocation.region = {
        startLine: threat.lineNumber,
        startColumn: 1
      };
    }

    locations.push(location);
  }

  // If no package path, create a generic location
  if (locations.length === 0) {
    locations.push({
      physicalLocation: {
        artifactLocation: {
          uri: 'package.json'
        }
      }
    });
  }

  return locations;
}

/**
 * Write SARIF output to file
 * @param {Object} sarif - SARIF object
 * @param {string} outputPath - Output file path
 * @returns {Promise<void>}
 */
async function writeSarifFile(sarif, outputPath) {
  const fs = require('fs').promises;
  const jsonString = JSON.stringify(sarif, null, 2);
  await fs.writeFile(outputPath, jsonString, 'utf8');
}

/**
 * Validate SARIF output
 * @param {Object} sarif - SARIF object
 * @returns {Object} Validation result
 */
function validateSarifOutput(sarif) {
  const errors = [];
  const warnings = [];

  // Basic structure validation
  if (!sarif.$schema) {
    errors.push('Missing $schema property');
  }

  if (!sarif.version) {
    errors.push('Missing version property');
  }

  if (!sarif.runs || !Array.isArray(sarif.runs)) {
    errors.push('Missing or invalid runs array');
  }

  if (sarif.runs && sarif.runs.length > 0) {
    const run = sarif.runs[0];
    
    if (!run.tool || !run.tool.driver) {
      errors.push('Missing tool driver information');
    }

    if (!run.results || !Array.isArray(run.results)) {
      errors.push('Missing or invalid results array');
    }

    // Validate results
    if (run.results) {
      run.results.forEach((result, index) => {
        if (!result.ruleId) {
          warnings.push(`Result ${index + 1}: Missing ruleId`);
        }

        if (!result.message || !result.message.text) {
          warnings.push(`Result ${index + 1}: Missing message text`);
        }

        if (!result.locations || !Array.isArray(result.locations)) {
          warnings.push(`Result ${index + 1}: Missing or invalid locations`);
        }
      });
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings
  };
}

module.exports = {
  generateSarifOutput,
  writeSarifFile,
  validateSarifOutput,
  SEVERITY_MAPPING,
  LEVEL_MAPPING,
  RULE_DEFINITIONS
};
