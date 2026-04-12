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
const THREAT_TO_CATEGORY: Record<ThreatType, RiskCategory> = {
  ANALYSIS_ERROR: 'integrity',
  CODE_GENERATION_ATTEMPT: 'integrity',
  COMMAND_INJECTION: 'integrity',
  CRYPTO_MINING: 'availability',
  DATA_EXFILTRATION: 'confidentiality',
  DEPENDENCY_CONFUSION: 'integrity',
  DEPENDENCY_CONFUSION_ACTIVITY: 'integrity',
  DEPENDENCY_CONFUSION_ERROR: 'availability',
  DEPENDENCY_CONFUSION_GIT_ACTIVITY: 'integrity',
  DEPENDENCY_CONFUSION_ML_ANOMALY: 'integrity',
  DEPENDENCY_CONFUSION_PATTERN: 'integrity',
  DEPENDENCY_CONFUSION_PREDICTIVE_RISK: 'integrity',
  DEPENDENCY_CONFUSION_SCOPE: 'integrity',
  DEPENDENCY_CONFUSION_SUSPICIOUS_NAME: 'integrity',
  DEPENDENCY_CONFUSION_TIMELINE: 'integrity',
  DYNAMIC_REQUIRE: 'integrity',
  ERROR_HANDLING_FAILURE: 'availability',
  EXECUTION_TIMEOUT: 'availability',
  FILE_ACCESS_ERROR: 'availability',
  FILE_ANALYSIS_ERROR: 'availability',
  INPUT_VALIDATION_ERROR: 'integrity',
  MALICIOUS_CODE: 'integrity',
  MALICIOUS_CODE_ERROR: 'availability',
  MALICIOUS_CODE_STRUCTURE: 'integrity',
  MEMORY_EXHAUSTION: 'availability',
  MODULE_LOADING_ATTEMPT: 'integrity',
  NETWORK_MANIPULATION: 'integrity',
  NLP_SECURITY_INDICATOR: 'integrity',
  OBFUSCATED_CODE: 'integrity',
  OBFUSCATED_IOC: 'integrity',
  OBFUSCATED_WALLET_CODE: 'integrity',
  PACKAGE_NOT_FOUND: 'availability',
  PARALLEL_FILE_ANALYSIS_ERROR: 'availability',
  PARALLEL_PROCESSING_ERROR: 'availability',
  PATH_TRAVERSAL: 'confidentiality',
  PATH_TRAVERSAL_ATTEMPT: 'confidentiality',
  PATH_VALIDATION_ERROR: 'integrity',
  SANDBOX_EXECUTION_ERROR: 'availability',
  SANDBOX_MEMORY_LIMIT: 'availability',
  SANDBOX_SECURITY_VIOLATION: 'integrity',
  SANDBOX_TIMEOUT: 'availability',
  SCAN_ERROR: 'availability',
  SECURITY_ERROR: 'integrity',
  SUPPLY_CHAIN_ATTACK: 'integrity',
  SUSPICIOUS_DEPENDENCY: 'integrity',
  SUSPICIOUS_FILE: 'integrity',
  SUSPICIOUS_FILE_SIZE: 'availability',
  SUSPICIOUS_FILE_TYPE: 'integrity',
  SUSPICIOUS_MODULE: 'integrity',
  SUSPICIOUS_PACKAGE_NAME: 'integrity',
  SUSPICIOUS_SCRIPT: 'integrity',
  TIMEOUT_EXCEEDED: 'availability',
  TYPOSQUATTING_RISK: 'integrity',
  UNKNOWN_ERROR: 'availability',
  VALIDATION_ERROR: 'integrity',
  VULNERABLE_PACKAGE: 'integrity',
  WALLET_HIJACKING: 'integrity',
  WALLET_ETHEREUMHIJACK: 'integrity',
  WALLET_TRANSACTIONREDIRECT: 'integrity',
  WALLET_ADDRESSSWAP: 'integrity',
  WALLET_MULTICHAIN: 'integrity',
  WALLET_OBFUSCATION: 'integrity',
  WALLET_NETWORKHOOKS: 'integrity',
};

function getThreatCategory(type: ThreatType): RiskCategory {
  const category = THREAT_TO_CATEGORY[type];
  if (!category && process.env['NODE_ENV'] !== 'production') {
    throw new Error(`Missing RiskCategory mapping for threat type: ${type}`);
  }
  return category ?? 'integrity';
}

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

    const cat = getThreatCategory(threat.type as ThreatType);
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
