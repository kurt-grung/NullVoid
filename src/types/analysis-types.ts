/**
 * Analysis-specific type definitions
 */

import { Threat } from './core';

export interface CodeAnalysis {
  /** Whether code is malicious */
  isMalicious: boolean;
  /** Analysis confidence score */
  confidence: number;
  /** Analysis reason */
  reason: string;
  /** Line number where issue was found */
  lineNumber?: number;
  /** Sample code snippet */
  sampleCode?: string;
  /** Detected patterns */
  patterns: string[];
  /** Entropy score */
  entropy: number;
  /** Obfuscation indicators */
  obfuscation: ObfuscationAnalysis;
}

export interface ObfuscationAnalysis {
  /** Whether code is obfuscated */
  isObfuscated: boolean;
  /** Obfuscation techniques detected */
  techniques: ObfuscationTechnique[];
  /** Obfuscation confidence score */
  confidence: number;
  /** Obfuscation complexity score */
  complexity: number;
}

export type ObfuscationTechnique = 
  | 'VARIABLE_MANGLING'
  | 'FUNCTION_MANGLING'
  | 'STRING_ENCODING'
  | 'HEX_ENCODING'
  | 'BASE64_ENCODING'
  | 'CHAR_CODE_ARRAYS'
  | 'DEAD_CODE_INJECTION'
  | 'CONTROL_FLOW_OBFUSCATION'
  | 'ANTI_DEBUGGING'
  | 'POLYMORPHIC_CODE';

export interface SandboxResult {
  /** Detected threats */
  threats: Threat[];
  /** Whether execution was safe */
  safe: boolean;
  /** Execution result */
  executionResult?: unknown;
  /** Execution error */
  executionError?: Error;
  /** Execution time in milliseconds */
  executionTime: number;
}
