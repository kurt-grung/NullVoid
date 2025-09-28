/**
 * Enhanced Configurable Rules System for NullVoid
 * Advanced detection patterns for sophisticated wallet hijacking and supply chain attacks
 */

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

/**
 * Advanced detection rules with comprehensive patterns
 */
const ENHANCED_RULES = {
  wallet_hijacking: {
    patterns: [
      // Direct wallet hijacking
      'window\\.ethereum\\s*=\\s*new\\s+Proxy',
      'Object\\.defineProperty\\s*\\(\\s*window\\s*,\\s*[\'"`]ethereum',
      'window\\.__defineGetter__\\s*\\(\\s*[\'"`]ethereum',
      'window\\.ethereum\\s*=\\s*.*?proxy',
      
      // Transaction manipulation
      'eth_sendTransaction.*?params.*?to\\s*[:=]',
      'params\\[0\\]\\.to\\s*=\\s*[\'"`]0x[a-fA-F0-9]{40}',
      'transaction\\.to\\s*=.*?attacker',
      'sendTransaction.*?replace.*?address',
      
      // Address replacement
      'replace\\s*\\(\\s*/0x[a-fA-F0-9]{40}/.*?,\\s*[\'"`]0x',
      '0x[a-fA-F0-9]{40}.*?//.*?(attacker|wallet|address)',
      '\\.replace\\s*\\(\\s*[\'"`]0x[a-fA-F0-9]{40}',
      
      // Multi-chain targeting
      'bitcoin.*?address.*?replace',
      'litecoin.*?L[a-km-zA-HJ-NP-Z1-9]{26,33}',
      'tron.*?T[a-km-zA-HJ-NP-Z1-9]{33}',
      'solana.*?[1-9A-HJ-NP-Za-km-z]{32,44}',
      'polygon.*?0x[a-fA-F0-9]{40}',
      'bsc.*?0x[a-fA-F0-9]{40}',
      
      // Legacy patterns (kept for backward compatibility)
      '_0x112fa8',
      'stealthProxyControl',
      'runmask',
      'newdlocal',
      'window.ethereum',
      'ethereum.request'
    ],
    severity: 'CRITICAL',
    description: 'Detects sophisticated wallet hijacking and transaction manipulation',
    confidence_threshold: 0.7
  },
  
  network_manipulation: {
    patterns: [
      // Network interception
      'XMLHttpRequest\\.prototype\\.open\\s*=',
      'fetch\\s*=\\s*.*?function',
      'Response\\.prototype\\.json\\s*=',
      'axios\\.interceptors',
      
      // Response manipulation
      'fetch.*override',
      'XMLHttpRequest.*intercept',
      'response\\.json.*replace',
      'blockchain.*address.*replace',
      
      // API hijacking
      'api\\.binance\\.com.*replace',
      'api\\.coinbase\\.com.*replace',
      'api\\.kraken\\.com.*replace',
      'api\\.bitfinex\\.com.*replace'
    ],
    severity: 'HIGH',
    description: 'Detects network response manipulation and API hijacking',
    confidence_threshold: 0.6
  },
  
  obfuscated_code: {
    patterns: [
      // Advanced obfuscation patterns
      'eval\\s*\\(\\s*String\\.fromCharCode',
      'Function\\s*\\(\\s*[\'"`]return',
      '_0x[a-f0-9]{4,6}\\s*\\(',
      '\\[\\s*[\'"`]\\\\x[0-9a-f]{2}',
      'atob\\s*\\(\\s*[\'"`][A-Za-z0-9+/=]+[\'"`]',
      
      // Legacy patterns
      'eval\\s*\\(',
      'new\\s+Function\\s*\\(',
      'fromCharCode',
      
      // Additional obfuscation techniques
      '\\[\\s*[\'"`][a-zA-Z0-9+/=]{50,}[\'"`]\\s*\\]',
      'String\\.fromCharCode\\(.*?\\d+.*?\\)',
      '\\w+\\s*=\\s*\\w+\\s*\\+\\s*\\w+\\s*\\+\\s*\\w+',
      '\\[\\s*[\'"`]\\\\u[0-9a-f]{4}[\'"`]\\s*\\]'
    ],
    entropy_threshold: 5.0,
    severity: 'HIGH',
    description: 'Detects obfuscated or suspicious code patterns',
    confidence_threshold: 0.8
  },
  
  suspicious_scripts: {
    patterns: [
      // Package lifecycle script attacks
      'postinstall.*curl',
      'postinstall.*wget',
      'postinstall.*npm.*install',
      'prepare.*download',
      'preinstall.*eval',
      'postinstall.*eval',
      'install.*bash.*-c',
      'postinstall.*node.*-e',
      
      // Command injection patterns
      'postinstall.*\\$\\(',
      'postinstall.*`',
      'postinstall.*exec',
      'postinstall.*spawn',
      'postinstall.*fork',
      
      // Network requests in scripts
      'postinstall.*http',
      'postinstall.*https',
      'postinstall.*fetch',
      'postinstall.*axios'
    ],
    severity: 'CRITICAL',
    description: 'Detects suspicious package lifecycle scripts and command injection',
    confidence_threshold: 0.9
  },
  
  crypto_mining: {
    patterns: [
      // Cryptocurrency mining patterns
      'crypto.*mining',
      'coin.*mining',
      'hashrate',
      'mining.*pool',
      'stratum.*pool',
      'mining.*rig',
      'gpu.*mining',
      'cpu.*mining',
      
      // Mining pool connections
      'stratum\\+tcp://',
      'mining.*pool.*connect',
      'hash.*rate.*calculation',
      'proof.*of.*work',
      'mining.*algorithm',
      
      // Browser mining
      'coinhive',
      'cryptonight',
      'web.*mining',
      'browser.*mining'
    ],
    severity: 'HIGH',
    description: 'Detects cryptocurrency mining code and browser mining',
    confidence_threshold: 0.7
  },
  
  supply_chain_attack: {
    patterns: [
      // Dependency confusion
      'package.*name.*confusion',
      'private.*registry.*bypass',
      'npm.*registry.*spoof',
      
      // Typosquatting patterns
      'package.*name.*typo',
      'similar.*package.*name',
      'confusing.*package.*name',
      
      // Malicious updates
      'package.*update.*malicious',
      'version.*bump.*attack',
      'semantic.*versioning.*abuse',
      
      // Package hijacking
      'package.*hijacking',
      'npm.*account.*compromise',
      'package.*maintainer.*attack'
    ],
    severity: 'CRITICAL',
    description: 'Detects supply chain attack patterns and dependency confusion',
    confidence_threshold: 0.8
  },
  
  data_exfiltration: {
    patterns: [
      // Data collection patterns
      'process\\.env\\..*collect',
      'localStorage.*collect',
      'sessionStorage.*collect',
      'cookie.*collect',
      
      // Network exfiltration
      'fetch.*data.*send',
      'XMLHttpRequest.*data.*send',
      'axios.*data.*send',
      'websocket.*data.*send',
      
      // File system access
      'fs\\.readFile.*sensitive',
      'fs\\.readdir.*sensitive',
      'fs\\.stat.*sensitive',
      
      // Process information
      'process\\.env',
      'process\\.argv',
      'process\\.cwd',
      'process\\.platform',
      'process\\.version'
    ],
    severity: 'HIGH',
    description: 'Detects data exfiltration and sensitive information collection',
    confidence_threshold: 0.6
  }
};

/**
 * Load rules from file (JSON or YAML)
 * @param {string} rulesPath - Path to rules file
 * @returns {object} Parsed rules object
 */
function loadRules(rulesPath) {
  if (!rulesPath || !fs.existsSync(rulesPath)) {
    return ENHANCED_RULES;
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
    return ENHANCED_RULES;
  }
}

/**
 * Merge custom rules with enhanced default rules
 * @param {object} customRules - Custom rules from file
 * @param {object} defaultRules - Default rules
 * @returns {object} Merged rules
 */
function mergeRules(customRules, defaultRules = ENHANCED_RULES) {
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
 * Apply enhanced rules to content analysis with confidence scoring
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
    
    let patternMatches = 0;
    let totalPatterns = ruleConfig.patterns.length;
    
    for (const pattern of ruleConfig.patterns) {
      try {
        const regex = new RegExp(pattern, 'gi');
        const matches = content.match(regex);
        
        if (matches) {
          patternMatches++;
          
          // Calculate confidence based on pattern matches and rule configuration
          const baseConfidence = ruleConfig.confidence_threshold || 0.5;
          const patternConfidence = Math.min(0.95, baseConfidence + (matches.length * 0.1));
          
          threats.push({
            type: `ENHANCED_RULE_${ruleName.toUpperCase()}`,
            message: ruleConfig.description || `Detected pattern: ${pattern}`,
            package: packageName,
            severity: ruleConfig.severity || 'MEDIUM',
            details: `Enhanced rule "${ruleName}" matched pattern: ${pattern}`,
            rule: ruleName,
            pattern: pattern,
            confidence: patternConfidence,
            matches: matches.length
          });
        }
      } catch (error) {
        // Skip invalid regex patterns
        console.warn(`Warning: Invalid regex pattern in rule ${ruleName}: ${pattern}`);
      }
    }
    
    // Add aggregate threat if multiple patterns match
    if (patternMatches > 1) {
      const aggregateConfidence = Math.min(0.95, (patternMatches / totalPatterns) * 0.8);
      threats.push({
        type: `AGGREGATE_${ruleName.toUpperCase()}`,
        message: `Multiple ${ruleName} patterns detected`,
        package: packageName,
        severity: ruleConfig.severity || 'MEDIUM',
        details: `${patternMatches} out of ${totalPatterns} patterns matched`,
        rule: ruleName,
        confidence: aggregateConfidence,
        patternMatches: patternMatches
      });
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
      ...ENHANCED_RULES,
      
      // Custom enterprise rules
      enterprise_threats: {
        patterns: [
          'company-internal-api',
          'staging-environment',
          'dev-secrets'
        ],
        severity: 'LOW',
        description: 'Enterprise-specific threat patterns',
        confidence_threshold: 0.3
      },
      
      competitor_analysis: {
        patterns: [
          'competitor-data-scraper',
          'market-analysis-tool',
          'price-monitoring'
        ],
        severity: 'HIGH',
        description: 'Detects competitor analysis tools',
        confidence_threshold: 0.8
      }
    },
    
    // Global configuration
    global_config: {
      entropy_threshold: 5.0,
      max_file_size: '10MB',
      scan_timeout: 30000,
      enable_verbose: false,
      confidence_threshold: 0.5
    },
    
    // Severity overrides
    severity_overrides: {
      'wallet_hijacking': 'CRITICAL',
      'network_manipulation': 'HIGH',
      'obfuscated_code': 'HIGH',
      'supply_chain_attack': 'CRITICAL',
      'data_exfiltration': 'HIGH'
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
    console.log(`Enhanced example rules file created: ${outputPath}`);
  } catch (error) {
    console.error(`Error creating example rules file: ${error.message}`);
  }
}

module.exports = {
  loadRules,
  mergeRules,
  applyRules,
  createExampleRules,
  ENHANCED_RULES
};
