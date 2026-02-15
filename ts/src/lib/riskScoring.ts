/**
 * Composite risk scoring for scan results.
 * Maps threats to C/I/A categories and computes overall risk.
 */

import type { Threat, SeverityLevel } from '../types/core';
import type { ThreatType } from '../types/core';
import { RISK_CONFIG } from './config';

export type RiskCategory = 'confidentiality' | 'integrity' | 'availability';

export interface RiskAssessment {
  overall: number;
  byCategory: Record<RiskCategory, number>;
  bySeverity: Record<SeverityLevel, number>;
}

/** Map threat types to C/I/A categories */
const THREAT_TO_CATEGORY: Partial<Record<ThreatType, RiskCategory>> = {
  DATA_EXFILTRATION: 'confidentiality',
  MALICIOUS_CODE: 'integrity',
  WALLET_HIJACKING: 'integrity',
  WALLET_ETHEREUMHIJACK: 'integrity',
  WALLET_TRANSACTIONREDIRECT: 'integrity',
  WALLET_ADDRESSSWAP: 'integrity',
  WALLET_MULTICHAIN: 'integrity',
  WALLET_OBFUSCATION: 'integrity',
  WALLET_NETWORKHOOKS: 'integrity',
  OBFUSCATED_WALLET_CODE: 'integrity',
  NETWORK_MANIPULATION: 'integrity',
  OBFUSCATED_CODE: 'integrity',
  SUSPICIOUS_SCRIPT: 'integrity',
  CRYPTO_MINING: 'availability',
  SUPPLY_CHAIN_ATTACK: 'integrity',
  PATH_TRAVERSAL: 'confidentiality',
  PATH_TRAVERSAL_ATTEMPT: 'confidentiality',
  COMMAND_INJECTION: 'integrity',
  DYNAMIC_REQUIRE: 'integrity',
  SUSPICIOUS_MODULE: 'integrity',
  OBFUSCATED_IOC: 'integrity',
  DEPENDENCY_CONFUSION: 'integrity',
  DEPENDENCY_CONFUSION_TIMELINE: 'integrity',
  DEPENDENCY_CONFUSION_SUSPICIOUS_NAME: 'integrity',
  DEPENDENCY_CONFUSION_SCOPE: 'integrity',
  DEPENDENCY_CONFUSION_GIT_ACTIVITY: 'integrity',
  DEPENDENCY_CONFUSION_PATTERN: 'integrity',
  DEPENDENCY_CONFUSION_ACTIVITY: 'integrity',
  DEPENDENCY_CONFUSION_ML_ANOMALY: 'integrity',
  DEPENDENCY_CONFUSION_PREDICTIVE_RISK: 'integrity',
  MALICIOUS_CODE_STRUCTURE: 'integrity',
  SUSPICIOUS_FILE: 'integrity',
  SUSPICIOUS_DEPENDENCY: 'integrity',
  NLP_SECURITY_INDICATOR: 'integrity',
  VULNERABLE_PACKAGE: 'integrity',
  SUSPICIOUS_PACKAGE_NAME: 'integrity',
  TYPOSQUATTING_RISK: 'integrity',
};

/**
 * Compute composite risk from threats.
 */
export function computeCompositeRisk(threats: Threat[]): RiskAssessment {
  const severityScores = RISK_CONFIG.SEVERITY_SCORES;
  const categoryWeights = RISK_CONFIG.CATEGORY_WEIGHTS;

  const bySeverity: Record<SeverityLevel, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
  };

  const byCategory: Record<RiskCategory, number> = {
    confidentiality: 0,
    integrity: 0,
    availability: 0,
  };

  const validSeverities: SeverityLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  for (const threat of threats) {
    const score = severityScores[threat.severity] ?? 0.5;
    const conf = (threat.confidence ?? 1) * score;

    if (validSeverities.includes(threat.severity as SeverityLevel)) {
      bySeverity[threat.severity as SeverityLevel] += conf;
    }

    const cat = THREAT_TO_CATEGORY[threat.type as ThreatType] ?? 'integrity';
    byCategory[cat] += conf;
  }

  // Normalize by category (0-1)
  const normByCategory: Record<RiskCategory, number> = {
    confidentiality: Math.min(1, byCategory.confidentiality),
    integrity: Math.min(1, byCategory.integrity),
    availability: Math.min(1, byCategory.availability),
  };

  // Overall: weighted sum of category scores, capped at 1
  const overall =
    normByCategory.confidentiality * (categoryWeights['confidentiality'] ?? 0.35) +
    normByCategory.integrity * (categoryWeights['integrity'] ?? 0.45) +
    normByCategory.availability * (categoryWeights['availability'] ?? 0.2);
  const overallCapped = Math.min(1, overall * 2);

  return {
    overall: Math.round(overallCapped * 100) / 100,
    byCategory: normByCategory,
    bySeverity,
  };
}
