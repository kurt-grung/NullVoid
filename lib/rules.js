/**
 * Configurable Rules System for NullVoid
 * Allows users to customize detection patterns via JSON/YAML files
 */

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

/**
 * Default detection rules
 */
const DEFAULT_RULES = {
  wallet_hijacking: {
    patterns: [
      '_0x112fa8',
      'stealthProxyControl',
      'runmask',
      'newdlocal',
      'window.ethereum',
      'ethereum.request'
    ],
    severity: 'HIGH',
    description: 'Detects wallet hijacking and transaction manipulation'
  },
  
  network_manipulation: {
    patterns: [
      'fetch.*override',
      'XMLHttpRequest.*intercept',
      'response.json.*replace',
      'blockchain.*address.*replace'
    ],
    severity: 'HIGH',
    description: 'Detects network response manipulation'
  },
  
  obfuscated_code: {
    patterns: [
      'eval(',
      'new Function(',
      'atob(',
      'fromCharCode'
    ],
    entropy_threshold: 5.0,
    severity: 'MEDIUM',
    description: 'Detects obfuscated or suspicious code patterns'
  },
  
  suspicious_scripts: {
    patterns: [
      'postinstall.*curl',
      'postinstall.*wget',
      'postinstall.*npm.*install',
      'prepare.*download'
    ],
    severity: 'HIGH',
    description: 'Detects suspicious package lifecycle scripts'
  },
  
  crypto_mining: {
    patterns: [
      'crypto.*mining',
      'coin.*mining',
      'hashrate',
      'mining.*pool'
    ],
    severity: 'MEDIUM',
    description: 'Detects cryptocurrency mining code'
  }
};

/**
 * Load rules from file (JSON or YAML)
 * @param {string} rulesPath - Path to rules file
 * @returns {object} Parsed rules object
 */
function loadRules(rulesPath) {
  if (!rulesPath || !fs.existsSync(rulesPath)) {
    return DEFAULT_RULES;
  }
  
  try {
    const fileContent = fs.readFileSync(rulesPath, 'utf8');
    const ext = path.extname(rulesPath).toLowerCase();
    
    if (ext === '.yaml' || ext === '.yml') {
      return yaml.load(fileContent);
    } else if (ext === '.json') {
      return JSON.parse(fileContent);
    } else {
      throw new Error(`Unsupported file format: ${ext}`);
    }
  } catch (error) {
    console.warn(`Warning: Could not load rules from ${rulesPath}: ${error.message}`);
    return DEFAULT_RULES;
  }
}

/**
 * Merge custom rules with default rules
 * @param {object} customRules - Custom rules from file
 * @param {object} defaultRules - Default rules
 * @returns {object} Merged rules
 */
function mergeRules(customRules, defaultRules = DEFAULT_RULES) {
  const merged = { ...defaultRules };
  
  if (customRules && typeof customRules === 'object') {
    for (const [ruleName, ruleConfig] of Object.entries(customRules)) {
      if (ruleConfig && typeof ruleConfig === 'object') {
        merged[ruleName] = {
          ...merged[ruleName],
          ...ruleConfig
        };
      }
    }
  }
  
  return merged;
}

/**
 * Apply rules to content analysis
 * @param {string} content - Content to analyze
 * @param {string} packageName - Package name
 * @param {object} rules - Rules configuration
 * @returns {Array} Array of detected threats
 */
function applyRules(content, packageName, rules) {
  const threats = [];
  
  for (const [ruleName, ruleConfig] of Object.entries(rules)) {
    if (!ruleConfig.patterns || !Array.isArray(ruleConfig.patterns)) {
      continue;
    }
    
    for (const pattern of ruleConfig.patterns) {
      try {
        const regex = new RegExp(pattern, 'gi');
        if (regex.test(content)) {
          threats.push({
            type: `CUSTOM_RULE_${ruleName.toUpperCase()}`,
            message: ruleConfig.description || `Detected pattern: ${pattern}`,
            package: packageName,
            severity: ruleConfig.severity || 'MEDIUM',
            details: `Custom rule "${ruleName}" matched pattern: ${pattern}`,
            rule: ruleName,
            pattern: pattern
          });
        }
      } catch (error) {
        // Skip invalid regex patterns
        console.warn(`Warning: Invalid regex pattern in rule ${ruleName}: ${pattern}`);
      }
    }
  }
  
  return threats;
}

/**
 * Create example rules file
 * @param {string} outputPath - Path to save example file
 * @param {string} format - File format ('json' or 'yaml')
 */
function createExampleRules(outputPath, format = 'yaml') {
  const exampleRules = {
    detection_rules: {
      ...DEFAULT_RULES,
      
      // Custom enterprise rules
      enterprise_threats: {
        patterns: [
          'company-internal-api',
          'staging-environment',
          'dev-secrets'
        ],
        severity: 'LOW',
        description: 'Enterprise-specific threat patterns'
      },
      
      competitor_analysis: {
        patterns: [
          'competitor-data-scraper',
          'market-analysis-tool',
          'price-monitoring'
        ],
        severity: 'HIGH',
        description: 'Detects competitor analysis tools'
      }
    },
    
    // Global configuration
    global_config: {
      entropy_threshold: 5.0,
      max_file_size: '10MB',
      scan_timeout: 30000,
      enable_verbose: false
    },
    
    // Severity overrides
    severity_overrides: {
      'wallet_hijacking': 'CRITICAL',
      'network_manipulation': 'HIGH',
      'obfuscated_code': 'MEDIUM'
    }
  };
  
  try {
    let content;
    if (format === 'json') {
      content = JSON.stringify(exampleRules, null, 2);
    } else {
      content = yaml.dump(exampleRules, { indent: 2 });
    }
    
    fs.writeFileSync(outputPath, content);
    console.log(`Example rules file created: ${outputPath}`);
  } catch (error) {
    console.error(`Error creating example rules file: ${error.message}`);
  }
}

module.exports = {
  loadRules,
  mergeRules,
  applyRules,
  createExampleRules,
  DEFAULT_RULES
};
