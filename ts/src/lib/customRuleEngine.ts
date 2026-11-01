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
  return undefined;
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
  const rules = resolveScanRules(options);
  if (!rules) {
    return baseThreats;
  }
  const customThreats = runCustomRuleEngine(content, filePath, { rules });
  return [...baseThreats, ...customThreats];
}
