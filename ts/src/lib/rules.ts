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
/**
 * Built-in rules. These run on every scan unless `builtinRules: false`, so each
 * pattern must be specific enough that it rarely matches ordinary code. Bare
 * keywords (`eval\(`, `process.env`, `window.ethereum`, prose such as
 * `package hijacking`) were removed because they flagged most real projects.
 */
export const ENHANCED_RULES: EnhancedRules = {
  wallet_hijacking: {
    patterns: [
      // Provider hijacking
      'window\\.ethereum\\s*=\\s*new\\s+Proxy',
      'Object\\.defineProperty\\s*\\(\\s*window\\s*,\\s*[\'"`]ethereum',
      'window\\.__defineGetter__\\s*\\(\\s*[\'"`]ethereum',
      'window\\.ethereum\\s*=\\s*.*?proxy',

      // Transaction manipulation
      'eth_sendTransaction[\\s\\S]{0,200}params[\\s\\S]{0,100}\\.to\\s*=\\s*[\'"`]0x[a-fA-F0-9]{40}',
      'params\\[0\\]\\.to\\s*=\\s*[\'"`]0x[a-fA-F0-9]{40}',
      '\\.to\\s*=\\s*[\'"`]0x[a-fA-F0-9]{40}[\'"`]',

      // Address replacement in intercepted responses
      '\\.replace\\s*\\(\\s*/0x[a-fA-F0-9]{40}',
      '\\.replace\\s*\\(\\s*[\'"`]0x[a-fA-F0-9]{40}[\'"`]\\s*,\\s*[\'"`]0x',
      '/\\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\\b/[gimsuy]*[\\s\\S]{0,60}\\.replace',
      '/T[A-Za-z1-9]{33}/[gimsuy]*[\\s\\S]{0,60}\\.replace',

      // Known malware markers (chalk/debug 2025 drainer, legacy samples)
      'stealthProxyControl',
      'runmask',
      'newdlocal',
      'checkethereumw',
      '_0x112fa8',
    ],
    severity: 'CRITICAL',
    description: 'Detects wallet provider hijacking and transaction/address manipulation',
    confidence_threshold: 0.7,
  },

  network_manipulation: {
    patterns: [
      // Prototype-level interception of network APIs
      'XMLHttpRequest\\.prototype\\.(?:open|send)\\s*=',
      'Response\\.prototype\\.(?:json|text)\\s*=',
      '(?:window|globalThis|global)\\.fetch\\s*=\\s*(?:async\\s*)?(?:function|\\()',
      'fetch\\s*=\\s*new\\s+Proxy',
      'WebSocket\\.prototype\\.send\\s*=',

      // Response rewriting targeting exchanges
      'api\\.(?:binance|coinbase|kraken|bitfinex)\\.com[\\s\\S]{0,200}\\.replace',
    ],
    severity: 'HIGH',
    description: 'Detects interception and rewriting of network responses',
    confidence_threshold: 0.6,
  },

  obfuscated_code: {
    patterns: [
      // Decode-then-execute chains
      'eval\\s*\\(\\s*String\\.fromCharCode',
      'eval\\s*\\(\\s*atob\\s*\\(',
      'eval\\s*\\(\\s*Buffer\\.from\\s*\\([^)]*[\'"`]base64',
      'new\\s+Function\\s*\\(\\s*atob\\s*\\(',

      // javascript-obfuscator output
      '_0x[a-f0-9]{4,6}\\s*\\(',
      '\\[\\s*[\'"`](?:\\\\x[0-9a-f]{2}){3,}',

      // Large embedded base64 payloads passed to a decoder
      'atob\\s*\\(\\s*[\'"`][A-Za-z0-9+/=]{200,}[\'"`]',
      'Buffer\\.from\\s*\\(\\s*[\'"`][A-Za-z0-9+/=]{200,}[\'"`]\\s*,\\s*[\'"`]base64',
    ],
    severity: 'HIGH',
    description: 'Detects decode-and-execute chains and obfuscator output',
    confidence_threshold: 0.7,
  },

  suspicious_scripts: {
    patterns: [
      // Lifecycle scripts that fetch and run remote code
      '"(?:pre|post)?install"\\s*:\\s*"[^"]*(?:curl|wget)[^"]*\\|\\s*(?:ba)?sh',
      '"(?:pre|post)?install"\\s*:\\s*"[^"]*node\\s+-e\\s',
      '"(?:pre|post)?install"\\s*:\\s*"[^"]*(?:bash|sh)\\s+-c\\s',
      '"(?:pre|post)?install"\\s*:\\s*"[^"]*powershell[^"]*-(?:e|enc|encodedcommand)\\b',
      '"(?:pre|post)?install"\\s*:\\s*"[^"]*base64\\s+(?:-d|--decode)',
      '"(?:pre|post)?install"\\s*:\\s*"[^"]*\\$\\(',

      // Code that writes and executes a dropped file
      'child_process[\\s\\S]{0,300}(?:writeFileSync|writeFile)[\\s\\S]{0,300}(?:exec|spawn|execFile)\\s*\\(',
      '(?:exec|spawn|execSync)\\s*\\(\\s*[\'"`](?:curl|wget)\\s[^\'"`]*\\|\\s*(?:ba)?sh',
    ],
    severity: 'CRITICAL',
    description: 'Detects lifecycle scripts and code paths that download and execute payloads',
    confidence_threshold: 0.9,
  },

  crypto_mining: {
    patterns: [
      'stratum\\+tcp://',
      'stratum\\+ssl://',
      'coinhive',
      'coin-hive',
      'cryptonight',
      'crypto-?loot',
      'xmrig',
      'minergate',
      'nicehash\\.com',
      '(?:monero|xmr)[\\s\\S]{0,80}pool',
    ],
    severity: 'HIGH',
    description: 'Detects cryptocurrency mining libraries and pool connections',
    confidence_threshold: 0.7,
  },

  data_exfiltration: {
    patterns: [
      // Environment serialised wholesale. Proximity-based env/credential +
      // network patterns moved to the AST capability analysis (capabilityAnalysis.ts),
      // which knows the difference between process.env.HTTP_PROXY and {...process.env}.
      'JSON\\.stringify\\s*\\(\\s*process\\.env\\s*\\)',
      'Buffer\\.from\\s*\\(\\s*JSON\\.stringify\\s*\\(\\s*process\\.env',

      // DNS tunnelling of collected data
      '\\.toString\\s*\\(\\s*[\'"`](?:base64|hex)[\'"`]\\s*\\)[\\s\\S]{0,120}dns\\.(?:resolve|lookup)',

      // Known exfiltration endpoints from published incidents
      'webhook\\.site/',
      'pipedream\\.net/',
      'interactsh\\.com',
      'oast\\.(?:fun|live|me|online|pro|site)',
      'burpcollaborator\\.net',
    ],
    severity: 'HIGH',
    description: 'Detects environment, credential and host data being sent off-machine',
    confidence_threshold: 0.6,
  },
};

/**
 * Load rules from file (JSON or YAML)
 * @param rulesPath - Path to rules file
 * @param options - Loading options
 * @returns Parsed rules object
 */
function parseRulesPayload(parsed: Record<string, unknown>): EnhancedRules {
  const raw =
    parsed['detection_rules'] && typeof parsed['detection_rules'] === 'object'
      ? (parsed['detection_rules'] as Record<string, unknown>)
      : parsed;
  return normalizeRules(raw as Record<string, Partial<RuleConfig>>);
}

export function normalizeRuleConfig(rule: Partial<RuleConfig>): RuleConfig {
  return {
    patterns: Array.isArray(rule.patterns) ? rule.patterns : [],
    severity: rule.severity ?? 'MEDIUM',
    description: rule.description ?? '',
    confidence_threshold:
      typeof rule.confidence_threshold === 'number' ? rule.confidence_threshold : 0.5,
    ...(rule.entropy_threshold !== undefined ? { entropy_threshold: rule.entropy_threshold } : {}),
  };
}

export function normalizeRules(rules: Record<string, Partial<RuleConfig>>): EnhancedRules {
  const normalized: EnhancedRules = {};
  for (const [name, config] of Object.entries(rules)) {
    if (config && typeof config === 'object') {
      normalized[name] = normalizeRuleConfig(config);
    }
  }
  return normalized;
}

export function parseRulesContent(
  content: string,
  format: 'json' | 'yaml' | 'auto' = 'auto'
): EnhancedRules {
  let parsed: Record<string, unknown>;
  if (format === 'yaml') {
    parsed = (yaml.load(content, { schema: yaml.JSON_SCHEMA }) as Record<string, unknown>) || {};
  } else if (format === 'json') {
    parsed = JSON.parse(content) as Record<string, unknown>;
  } else {
    const trimmed = content.trim();
    parsed =
      trimmed.startsWith('{') || trimmed.startsWith('[')
        ? (JSON.parse(content) as Record<string, unknown>)
        : (yaml.load(content, { schema: yaml.JSON_SCHEMA }) as Record<string, unknown>) || {};
  }
  return parseRulesPayload(parsed);
}

export function parseRulesObject(value: unknown): EnhancedRules {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Rules must be a JSON object');
  }
  return parseRulesPayload(value as Record<string, unknown>);
}

export function loadRules(rulesPath: string, options: RulesLoadingOptions = {}): EnhancedRules {
  if (!rulesPath || !fs.existsSync(rulesPath)) {
    if (options.mergeWithDefaults === false) {
      throw new Error(`Rules file not found: ${rulesPath}`);
    }
    return ENHANCED_RULES;
  }

  try {
    const fileContent = fs.readFileSync(rulesPath, 'utf8');
    const ext = path.extname(rulesPath).toLowerCase();
    const format =
      options.format ??
      (ext === '.yaml' || ext === '.yml' ? 'yaml' : ext === '.json' ? 'json' : 'auto');
    const parsedRules = parseRulesContent(fileContent, format);

    if (options.validateRules) {
      const { valid, errors } = validateRules(parsedRules);
      if (!valid) {
        throw new Error(errors.join('; '));
      }
    }

    if (options.mergeWithDefaults !== false) {
      return mergeRules(parsedRules);
    }

    return parsedRules;
  } catch (error) {
    if (options.mergeWithDefaults === false) {
      throw error;
    }
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
export function mergeRules(
  customRules: EnhancedRules,
  defaultRules: EnhancedRules = ENHANCED_RULES
): EnhancedRules {
  const merged = { ...defaultRules };

  if (customRules && typeof customRules === 'object') {
    for (const [ruleName, ruleConfig] of Object.entries(customRules)) {
      if (ruleConfig && typeof ruleConfig === 'object') {
        merged[ruleName] = {
          ...merged[ruleName],
          ...ruleConfig,
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
export function applyRules(
  content: string,
  packageName: string,
  rules: EnhancedRules
): ThreatDetectionResult[] {
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
          const patternConfidence = Math.min(0.95, baseConfidence + matches.length * 0.1);

          threats.push({
            type: `ENHANCED_RULE_${ruleName.toUpperCase()}`,
            message: ruleConfig.description || `Detected pattern: ${pattern}`,
            filePath: packageName,
            severity: ruleConfig.severity || 'MEDIUM',
            details: `Enhanced rule "${ruleName}" matched pattern: ${pattern}`,
            rule: ruleName,
            pattern: pattern,
            confidence: patternConfidence,
            matches: matches.length,
          });
        }
      } catch {
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
        patternMatches: patternMatches,
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
        patterns: ['company-internal-api', 'staging-environment', 'dev-secrets'],
        severity: 'LOW' as const,
        description: 'Enterprise-specific threat patterns',
        confidence_threshold: 0.3,
      },

      competitor_analysis: {
        patterns: ['competitor-data-scraper', 'market-analysis-tool', 'price-monitoring'],
        severity: 'HIGH' as const,
        description: 'Detects competitor analysis tools',
        confidence_threshold: 0.8,
      },
    },

    // Global configuration
    global_config: {
      entropy_threshold: 5.0,
      max_file_size: '10MB',
      scan_timeout: 30000,
      enable_verbose: false,
      confidence_threshold: 0.5,
    },

    // Severity overrides
    severity_overrides: {
      wallet_hijacking: 'CRITICAL' as const,
      network_manipulation: 'HIGH' as const,
      obfuscated_code: 'HIGH' as const,
      suspicious_scripts: 'CRITICAL' as const,
      crypto_mining: 'HIGH' as const,
      data_exfiltration: 'HIGH' as const,
    },
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

    if (
      !ruleConfig.severity ||
      !['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(ruleConfig.severity)
    ) {
      errors.push(`Rule ${ruleName} has invalid severity: ${ruleConfig.severity}`);
    }

    if (
      typeof ruleConfig.confidence_threshold !== 'number' ||
      ruleConfig.confidence_threshold < 0 ||
      ruleConfig.confidence_threshold > 1
    ) {
      errors.push(
        `Rule ${ruleName} has invalid confidence_threshold: ${ruleConfig.confidence_threshold}`
      );
    }

    // Validate regex patterns
    if (ruleConfig.patterns) {
      for (const pattern of ruleConfig.patterns) {
        try {
          new RegExp(pattern, 'gi');
        } catch {
          errors.push(`Rule ${ruleName} has invalid regex pattern: ${pattern}`);
        }
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors,
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
export function createRulesEngine(
  rules: EnhancedRules = ENHANCED_RULES,
  options: RulesLoadingOptions = {}
): RulesEngine {
  return new RulesEngine(rules, options);
}
