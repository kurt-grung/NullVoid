/**
 * Threat-specific type definitions
 */

export interface WalletHijackingThreat {
  type: 'WALLET_HIJACKING';
  walletType: 'ethereum' | 'bitcoin' | 'multi-chain';
  attackVector: 'transaction_redirect' | 'address_swap' | 'proxy_hijack';
  confidence: number;
  affectedWallets: string[];
}

export interface NetworkManipulationThreat {
  type: 'NETWORK_MANIPULATION';
  manipulationType: 'request_intercept' | 'response_modify' | 'dns_hijack';
  targetDomains: string[];
  confidence: number;
}

export interface StealthControlsThreat {
  type: 'STEALTH_CONTROLS';
  stealthType: 'anti_debug' | 'vm_detection' | 'timing_attack';
  techniques: string[];
  confidence: number;
}

export interface DependencyConfusionThreat {
  type: 'DEPENDENCY_CONFUSION';
  confusionType: 'timeline' | 'scope' | 'pattern' | 'activity';
  packageName: string;
  suspiciousIndicators: string[];
  confidence: number;
  timelineAnalysis?: TimelineAnalysis;
  scopeAnalysis?: ScopeAnalysis;
}

export interface TimelineAnalysis {
  packageAge: number;
  suspiciousTiming: boolean;
  rapidPublishing: boolean;
  versionGaps: boolean;
}

export interface ScopeAnalysis {
  scopeOwnership: boolean;
  namingPatterns: string[];
  suspiciousScope: boolean;
}
