export {
  loadRules,
  applyRules,
  validateRules,
  createRulesEngine,
  parseRulesObject,
  parseRulesContent,
  normalizeRules,
  createExampleRules,
  ENHANCED_RULES,
  type RuleConfig,
  type EnhancedRules,
  type ThreatDetectionResult,
  type RulesLoadingOptions,
} from './rules';

import {
  loadRules,
  applyRules,
  mergeRules,
  ENHANCED_RULES,
  parseRulesObject,
  type EnhancedRules,
  type RulesLoadingOptions,
} from './rules';
import type { ScanOptions, Threat } from '../types/core';

export interface CustomRuleEngineOptions extends RulesLoadingOptions {
  rulesPath?: string;
  rules?: EnhancedRules;
}

/**
 * Resolve the rule set for a scan.
 *
 * - Inline `rules` or a `rulesFile` are merged with the built-in ENHANCED_RULES
 *   unless `mergeRulesWithDefaults === false`.
 * - With no custom rules, the built-in ENHANCED_RULES (wallet hijacking, network
 *   manipulation, ...) are applied. Set `builtinRules: false` to run only the
 *   generic structural detection in `detectMalware`.
 */
export function resolveScanRules(options: ScanOptions): EnhancedRules | undefined {
  if (options.rules) {
    const parsed = parseRulesObject(options.rules);
    return options.mergeRulesWithDefaults === false ? parsed : mergeRules(parsed);
  }
  if (options.rulesFile) {
    const loadOpts: RulesLoadingOptions = {
      mergeWithDefaults: options.mergeRulesWithDefaults !== false,
    };
    if (options.validateRules) {
      loadOpts.validateRules = true;
    }
    return loadRules(options.rulesFile, loadOpts);
  }
  if (options.builtinRules === false) {
    return undefined;
  }
  return ENHANCED_RULES;
}

/**
 * Rules are resolved once per ScanOptions object. Without this cache a rules
 * file was re-read and re-parsed for every scanned file.
 */
const resolvedRulesCache = new WeakMap<ScanOptions, EnhancedRules | undefined>();

function resolveScanRulesCached(options: ScanOptions): EnhancedRules | undefined {
  if (resolvedRulesCache.has(options)) {
    return resolvedRulesCache.get(options);
  }
  const rules = resolveScanRules(options);
  resolvedRulesCache.set(options, rules);
  return rules;
}

export function runCustomRuleEngine(
  content: string,
  filePath: string,
  options: CustomRuleEngineOptions = {}
): Threat[] {
  const rules =
    options.rules ?? (options.rulesPath ? loadRules(options.rulesPath, options) : ENHANCED_RULES);
  const detections = applyRules(content, filePath, rules);
  return detections.map((d) => ({
    type: d.type as Threat['type'],
    message: d.message,
    filePath: d.filePath,
    filename: filePath.split('/').pop() ?? filePath,
    severity: d.severity,
    details: d.details,
    confidence: Math.round(d.confidence * 100),
  }));
}

export function detectFileThreats(
  content: string,
  filePath: string,
  options: ScanOptions,
  detectMalware: (content: string, filePath?: string) => Threat[]
): Threat[] {
  const baseThreats = detectMalware(content, filePath);
  const rules = resolveScanRulesCached(options);
  if (!rules) {
    return baseThreats;
  }
  const customThreats = runCustomRuleEngine(content, filePath, { rules });
  return [...baseThreats, ...customThreats];
}
