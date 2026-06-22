export {
  loadRules,
  applyRules,
  validateRules,
  createRulesEngine,
  ENHANCED_RULES,
  type RuleConfig,
  type EnhancedRules,
  type ThreatDetectionResult,
  type RulesLoadingOptions,
} from './rules';

import { loadRules, applyRules, ENHANCED_RULES, type RulesLoadingOptions } from './rules';
import type { Threat } from '../types/core';

export interface CustomRuleEngineOptions extends RulesLoadingOptions {
  rulesPath?: string;
}

export function runCustomRuleEngine(
  content: string,
  filePath: string,
  options: CustomRuleEngineOptions = {}
): Threat[] {
  const rules = options.rulesPath ? loadRules(options.rulesPath, options) : ENHANCED_RULES;
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
