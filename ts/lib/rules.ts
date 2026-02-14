/**
 * Enhanced Configurable Rules System for NullVoid
 * Advanced detection patterns for sophisticated wallet hijacking and supply chain attacks
 * Migrated from JavaScript to TypeScript with enhanced type safety
 */

import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';

/**
 * Rule configuration interface
 */
export interface RuleConfig {
  patterns: string[];
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  confidence_threshold: number;
  entropy_threshold?: number;
}

/**
 * Enhanced rules interface
 */
export interface EnhancedRules {
  [ruleName: string]: RuleConfig;
}

/**
 * Threat detection result interface
 */
export interface ThreatDetectionResult {
  type: string;
  message: string;
  filePath: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  details: string;
  rule: string;
  pattern: string;
  confidence: number;
  matches: number;
  patternMatches?: number;
}

/**
 * Rules loading options interface
 */
export interface RulesLoadingOptions {
  format?: 'json' | 'yaml' | 'auto';
  mergeWithDefaults?: boolean;
  validateRules?: boolean;
}

/**
 * Advanced detection rules with comprehensive patterns
 */
export const ENHANCED_RULES: EnhancedRules = {
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
 * @param rulesPath - Path to rules file
 * @param options - Loading options
 * @returns Parsed rules object
 */
export function loadRules(rulesPath: string, options: RulesLoadingOptions = {}): EnhancedRules {
  if (!rulesPath || !fs.existsSync(rulesPath)) {
    return ENHANCED_RULES;
  }
  
  try {
    const fileContent = fs.readFileSync(rulesPath, 'utf8');
    const ext = path.extname(rulesPath).toLowerCase();
    
    let parsedRules: any;
    
    if (ext === '.yaml' || ext === '.yml' || options.format === 'yaml') {
      parsedRules = yaml.load(fileContent, { schema: yaml.JSON_SCHEMA });
    } else if (ext === '.json' || options.format === 'json') {
      parsedRules = JSON.parse(fileContent);
    } else {
      throw new Error(`Unsupported file format: ${ext}`);
    }
    
    // Extract rules from nested structure if present
    if (parsedRules.detection_rules) {
      parsedRules = parsedRules.detection_rules;
    }
    
    // Merge with defaults if requested
    if (options.mergeWithDefaults !== false) {
      return mergeRules(parsedRules);
    }
    
    return parsedRules as EnhancedRules;
  } catch (error) {
    console.warn(`Warning: Could not load rules from ${rulesPath}: ${(error as Error).message}`);
    return ENHANCED_RULES;
  }
}

/**
 * Merge custom rules with enhanced default rules
 * @param customRules - Custom rules from file
 * @param defaultRules - Default rules
 * @returns Merged rules
 */
export function mergeRules(customRules: EnhancedRules, defaultRules: EnhancedRules = ENHANCED_RULES): EnhancedRules {
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
 * @param content - Content to analyze
 * @param packageName - Package name
 * @param rules - Rules configuration
 * @returns Array of detected threats
 */
export function applyRules(content: string, packageName: string, rules: EnhancedRules): ThreatDetectionResult[] {
  const threats: ThreatDetectionResult[] = [];
  
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
            filePath: packageName,
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
        filePath: packageName,
        severity: ruleConfig.severity || 'MEDIUM',
        details: `${patternMatches} out of ${totalPatterns} patterns matched`,
        rule: ruleName,
        pattern: '',
        confidence: aggregateConfidence,
        matches: 0,
        patternMatches: patternMatches
      });
    }
  }
  
  return threats;
}

/**
 * Create example rules file
 * @param outputPath - Path to save example file
 * @param format - File format ('json' or 'yaml')
 */
export function createExampleRules(outputPath: string, format: 'json' | 'yaml' = 'yaml'): void {
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
        severity: 'LOW' as const,
        description: 'Enterprise-specific threat patterns',
        confidence_threshold: 0.3
      },
      
      competitor_analysis: {
        patterns: [
          'competitor-data-scraper',
          'market-analysis-tool',
          'price-monitoring'
        ],
        severity: 'HIGH' as const,
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
      'wallet_hijacking': 'CRITICAL' as const,
      'network_manipulation': 'HIGH' as const,
      'obfuscated_code': 'HIGH' as const,
      'supply_chain_attack': 'CRITICAL' as const,
      'data_exfiltration': 'HIGH' as const
    }
  };
  
  try {
    let content: string;
    if (format === 'json') {
      content = JSON.stringify(exampleRules, null, 2);
    } else {
      content = yaml.dump(exampleRules, { indent: 2 });
    }
    
    fs.writeFileSync(outputPath, content);
    console.log(`Enhanced example rules file created: ${outputPath}`);
  } catch (error) {
    console.error(`Error creating example rules file: ${(error as Error).message}`);
  }
}

/**
 * Validate rules configuration
 * @param rules - Rules to validate
 * @returns Validation result
 */
export function validateRules(rules: EnhancedRules): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  for (const [ruleName, ruleConfig] of Object.entries(rules)) {
    if (!ruleConfig) {
      errors.push(`Rule ${ruleName} is null or undefined`);
      continue;
    }
    
    if (!ruleConfig.patterns || !Array.isArray(ruleConfig.patterns)) {
      errors.push(`Rule ${ruleName} missing or invalid patterns array`);
    }
    
    if (!ruleConfig.severity || !['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(ruleConfig.severity)) {
      errors.push(`Rule ${ruleName} has invalid severity: ${ruleConfig.severity}`);
    }
    
    if (typeof ruleConfig.confidence_threshold !== 'number' || ruleConfig.confidence_threshold < 0 || ruleConfig.confidence_threshold > 1) {
      errors.push(`Rule ${ruleName} has invalid confidence_threshold: ${ruleConfig.confidence_threshold}`);
    }
    
    // Validate regex patterns
    if (ruleConfig.patterns) {
      for (const pattern of ruleConfig.patterns) {
        try {
          new RegExp(pattern, 'gi');
        } catch (error) {
          errors.push(`Rule ${ruleName} has invalid regex pattern: ${pattern}`);
        }
      }
    }
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Rules engine class
 */
export class RulesEngine {
  private rules: EnhancedRules;
  private options: RulesLoadingOptions;

  constructor(rules: EnhancedRules = ENHANCED_RULES, options: RulesLoadingOptions = {}) {
    this.rules = rules;
    this.options = options;
  }

  /**
   * Load rules from file
   * @param rulesPath - Path to rules file
   * @returns Promise resolving to loaded rules
   */
  async loadRulesFromFile(rulesPath: string): Promise<EnhancedRules> {
    this.rules = loadRules(rulesPath, this.options);
    return this.rules;
  }

  /**
   * Apply rules to content
   * @param content - Content to analyze
   * @param packageName - Package name
   * @returns Array of detected threats
   */
  applyRules(content: string, packageName: string): ThreatDetectionResult[] {
    return applyRules(content, packageName, this.rules);
  }

  /**
   * Merge custom rules
   * @param customRules - Custom rules to merge
   */
  mergeRules(customRules: EnhancedRules): void {
    this.rules = mergeRules(customRules, this.rules);
  }

  /**
   * Validate current rules
   * @returns Validation result
   */
  validateRules(): { valid: boolean; errors: string[] } {
    return validateRules(this.rules);
  }

  /**
   * Get current rules
   * @returns Current rules
   */
  getRules(): EnhancedRules {
    return { ...this.rules };
  }

  /**
   * Update rules
   * @param rules - New rules
   */
  updateRules(rules: EnhancedRules): void {
    this.rules = rules;
  }

  /**
   * Get rule by name
   * @param ruleName - Rule name
   * @returns Rule configuration or undefined
   */
  getRule(ruleName: string): RuleConfig | undefined {
    return this.rules[ruleName];
  }

  /**
   * Add or update rule
   * @param ruleName - Rule name
   * @param ruleConfig - Rule configuration
   */
  setRule(ruleName: string, ruleConfig: RuleConfig): void {
    this.rules[ruleName] = ruleConfig;
  }

  /**
   * Remove rule
   * @param ruleName - Rule name
   */
  removeRule(ruleName: string): void {
    delete this.rules[ruleName];
  }

  /**
   * Get all rule names
   * @returns Array of rule names
   */
  getRuleNames(): string[] {
    return Object.keys(this.rules);
  }

  /**
   * Create example rules file
   * @param outputPath - Output path
   * @param format - File format
   */
  createExampleRules(outputPath: string, format: 'json' | 'yaml' = 'yaml'): void {
    createExampleRules(outputPath, format);
  }
}

/**
 * Create a new rules engine
 * @param rules - Initial rules
 * @param options - Loading options
 * @returns New rules engine instance
 */
export function createRulesEngine(rules: EnhancedRules = ENHANCED_RULES, options: RulesLoadingOptions = {}): RulesEngine {
  return new RulesEngine(rules, options);
}

