/**
 * Centralized Malware Detection Utilities
 * Reusable patterns and functions for detecting malicious code
 */

import parser from '@babel/parser';
import traverse from '@babel/traverse';
import * as t from '@babel/types';
import { isNullVoidCode, isTestFile } from './nullvoidDetection';
import { DETECTION_CONFIG } from './config';

/**
 * Analyze code structure for malicious patterns
 */
export function analyzeCodeStructure(code: string): {
  isMalicious: boolean;
  confidence: number;
  reason: string;
  lineNumber?: number;
  sampleCode?: string;
  patterns: string[];
  entropy: number;
  obfuscation: {
    isObfuscated: boolean;
    techniques: string[];
    confidence: number;
    complexity: number;
  };
} {
  const patterns: string[] = [];
  const obfuscationTechniques: string[] = [];
  let confidence = 0;
  let reason = '';
  let lineNumber: number | undefined;
  let sampleCode: string | undefined;
  
  // Calculate entropy
  const entropy = calculateShannonEntropy(code);
  
  // Variable name mangling detection (exact pattern from original)
  const variableManglingPattern = /const\s+[a-z]\d+\s*=\s*[A-Z]\s*,\s*[a-z]\d+\s*=\s*[A-Z]/g;
  const manglingMatches = code.match(variableManglingPattern);
  if (manglingMatches && manglingMatches.length > 0) {
    patterns.push('Variable name mangling');
    obfuscationTechniques.push('Variable name mangling');
    confidence += 30;
    reason += `Variable name mangling detected (${manglingMatches.length} instances). `;
  }
  
  // Massive obfuscated code blob detection (exact logic from original)
  if (code.length > 5000) {
    patterns.push('Massive obfuscated code blob');
    obfuscationTechniques.push('Code blob obfuscation');
    confidence += 25;
    reason += `Massive obfuscated code blob detected (${code.length} characters). `;
  }
  
  // Hex encoding arrays detection (exact pattern from original)
  const hexArrayPattern = /\[(0x[0-9a-fA-F]+,\s*){3,}/g;
  const hexMatches = code.match(hexArrayPattern);
  if (hexMatches && hexMatches.length > 0) {
    patterns.push('Hex encoding arrays');
    obfuscationTechniques.push('Hex encoding');
    confidence += 20;
    reason += `Hex encoding arrays detected (${hexMatches.length} instances). `;
  }
  
  // Code appended to legitimate module.exports detection (exact pattern from original)
  const moduleExportPattern = /module\.exports\s*=\s*[^;]+;\s*const\s+[a-z]\d+\s*=\s*[A-Z]/g;
  const moduleExportMatches = code.match(moduleExportPattern);
  if (moduleExportMatches && moduleExportMatches.length > 0) {
    patterns.push('Code appended to legitimate module.exports');
    obfuscationTechniques.push('Module export manipulation');
    confidence += 35;
    reason += `Code appended to legitimate module.exports detected. `;
  }
  
  // High entropy detection (exact logic from original)
  if (entropy > 4.5) {
    patterns.push('High entropy');
    obfuscationTechniques.push('High entropy obfuscation');
    confidence += 15;
    reason += `High entropy detected (${entropy.toFixed(2)}). `;
  }
  
  // Determine if malicious
  const isMalicious = confidence > 50;
  
  if (isMalicious) {
    // Calculate final confidence (exact logic from original)
    confidence = Math.min(confidence, 150); // Cap at 150%
    reason = `MALICIOUS CODE DETECTED: ${reason}Confidence: ${confidence}%`;
    
    // Find sample code (exact logic from original)
    const lines = code.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line && (line.match(variableManglingPattern) || line.match(moduleExportPattern))) {
        lineNumber = i + 1;
        const cleanLine = line.trim();
        
        // Find where malware starts (simplified version of detectMalwareStart)
        let malwareStart = -1;
        if (line.match(moduleExportPattern)) {
          // For module.exports pattern, find where legitimate code ends
          const moduleExportEnd = cleanLine.indexOf(';');
          if (moduleExportEnd !== -1) {
            malwareStart = moduleExportEnd + 1;
            // Skip whitespace
            while (malwareStart < cleanLine.length && /\s/.test(cleanLine.charAt(malwareStart))) {
              malwareStart++;
            }
          }
        } else if (line.match(variableManglingPattern)) {
          // For variable mangling, find the pattern
          const match = line.match(variableManglingPattern);
          if (match && match.index !== undefined) {
            malwareStart = match.index;
          }
        }
        
        if (malwareStart !== -1) {
          // Show only the malicious part with ... prefix
          const attackPart = cleanLine.substring(malwareStart, malwareStart + 60);
          sampleCode = '... ' + attackPart + '...';
        } else {
          // Fallback: show the line without excessive whitespace
          sampleCode = cleanLine.substring(0, 80) + (cleanLine.length > 80 ? '...' : '');
        }
        break;
      }
    }
  }
  
  const result: any = {
    isMalicious,
    confidence,
    reason,
    patterns,
    entropy,
    obfuscation: {
      isObfuscated: obfuscationTechniques.length > 0,
      techniques: obfuscationTechniques,
      confidence: Math.min(confidence, 100),
      complexity: obfuscationTechniques.length
    }
  };
  
  if (lineNumber !== undefined) {
    result.lineNumber = lineNumber;
  }
  
  if (sampleCode !== undefined) {
    result.sampleCode = sampleCode;
  }
  
  return result;
}

/**
 * Calculate Shannon entropy of a string
 */
export function calculateShannonEntropy(str: string): number {
  const freq: { [key: string]: number } = {};
  for (let i = 0; i < str.length; i++) {
    const char = str.charAt(i);
    freq[char] = (freq[char] || 0) + 1;
  }
  
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  
  return entropy;
}

/**
 * Detect wallet hijacking patterns
 */
export function detectWalletHijacking(code: string, fileName: string): Array<{
  type: string;
  message: string;
  package: string;
  severity: string;
  details: string;
  confidence?: number;
}> {
  const threats: Array<{
    type: string;
    message: string;
    package: string;
    severity: string;
    details: string;
    confidence?: number;
  }> = [];
  
  // Check for window.ethereum modifications
  if (code.includes('window.ethereum') && !isNullVoidCode(fileName)) {
    threats.push({
      type: 'WALLET_HIJACKING',
      message: 'Code modifies window.ethereum property',
      package: fileName,
      severity: 'CRITICAL',
      details: 'Detected window.ethereum usage which could hijack wallet connections',
      confidence: 0.9
    });
  }
  
  return threats;
}

/**
 * Detect obfuscated IoCs
 */
export function detectObfuscatedIoCs(content: string, filePath: string): Array<{
  type: string;
  message: string;
  package: string;
  severity: string;
  details: string;
  confidence?: number;
}> {
  const threats: Array<{
    type: string;
    message: string;
    package: string;
    severity: string;
    details: string;
    confidence?: number;
  }> = [];
  
  // Check for obfuscated URLs, IPs, domains
  const iocPatterns = DETECTION_CONFIG.IOC_PATTERNS;
  
  for (const [patternName, pattern] of Object.entries(iocPatterns)) {
    const matches = content.match(pattern as RegExp);
    if (matches && !isNullVoidCode(filePath)) {
      threats.push({
        type: 'OBFUSCATED_IOC',
        message: `Obfuscated ${patternName} detected`,
        package: filePath,
        severity: 'HIGH',
        details: `Detected obfuscated ${patternName} which could be used for malicious communication`,
        confidence: 0.8
      });
    }
  }
  
  return threats;
}

/**
 * Detect dynamic requires
 */
export function detectDynamicRequires(content: string, filePath: string): Array<{
  type: string;
  message: string;
  package: string;
  severity: string;
  details: string;
  confidence?: number;
}> {
  const threats: Array<{
    type: string;
    message: string;
    package: string;
    severity: string;
    details: string;
    confidence?: number;
  }> = [];
  
  // Check for dynamic require patterns
  const dynamicRequirePattern = DETECTION_CONFIG.DYNAMIC_REQUIRE_PATTERNS;
  
  for (const [patternName, pattern] of Object.entries(dynamicRequirePattern)) {
    const matches = content.match(pattern as RegExp);
    if (matches && !isNullVoidCode(filePath)) {
      threats.push({
        type: 'DYNAMIC_REQUIRE',
        message: `Dynamic ${patternName} detected`,
        package: filePath,
        severity: 'MEDIUM',
        details: `Detected dynamic ${patternName} which could load malicious modules`,
        confidence: 0.7
      });
    }
  }
  
  return threats;
}

/**
 * Advanced AST Analysis for JavaScript code
 */
export function analyzeJavaScriptAST(code: string, packageName: string): Array<{
  type: string;
  message: string;
  package: string;
  severity: string;
  details: string;
  lineNumber?: number;
  sampleCode?: string;
}> {
  const threats: Array<{
    type: string;
    message: string;
    package: string;
    severity: string;
    details: string;
    lineNumber?: number;
    sampleCode?: string;
  }> = [];
  
  // SMART DETECTION: Analyze code structure and patterns
  const codeAnalysis = analyzeCodeStructure(code);
  if (codeAnalysis.isMalicious && !isNullVoidCode(packageName) && !isTestFile(packageName)) {
    const threat: any = {
      type: 'MALICIOUS_CODE_STRUCTURE',
      message: 'Code structure indicates malicious obfuscated content',
      package: packageName,
      severity: 'CRITICAL',
      details: codeAnalysis.reason
    };
    
    if (codeAnalysis.lineNumber !== undefined) {
      threat.lineNumber = codeAnalysis.lineNumber;
    }
    
    if (codeAnalysis.sampleCode !== undefined) {
      threat.sampleCode = codeAnalysis.sampleCode;
    }
    
    threats.push(threat);
  }
  
  try {
    // Parse JavaScript code into AST
    const ast = parser.parse(code, {
      sourceType: 'module',
      allowImportExportEverywhere: true,
      allowReturnOutsideFunction: true,
      plugins: ['jsx', 'typescript', 'decorators-legacy']
    });
    
    // Analyze AST for malicious patterns
    traverse(ast, {
      // Detect window.ethereum modifications
      AssignmentExpression(path: any) {
        if (t.isMemberExpression(path.node.left)) {
          const object = path.node.left.object;
          const property = path.node.left.property;
          
          if (t.isIdentifier(object, { name: 'window' }) && 
              t.isIdentifier(property, { name: 'ethereum' })) {
            threats.push({
              type: 'WALLET_HIJACKING',
              message: 'Code modifies window.ethereum property',
              package: packageName,
              severity: 'CRITICAL',
              details: 'Detected assignment to window.ethereum which could hijack wallet connections'
            });
          }
        }
      },
      
      // Detect fetch/XMLHttpRequest overrides and eval usage
      CallExpression(path: any) {
        const callee = path.node.callee;
        
        // Detect fetch/XMLHttpRequest overrides
        if (t.isMemberExpression(callee)) {
          const property = callee.property;
          
          if (t.isIdentifier(property, { name: 'override' }) ||
              t.isIdentifier(property, { name: 'replace' })) {
            threats.push({
              type: 'NETWORK_MANIPULATION',
              message: 'Code contains function override patterns',
              package: packageName,
              severity: 'HIGH',
              details: 'Detected function override that could manipulate network requests'
            });
          }
        }
        
        // Detect eval usage
        if (t.isIdentifier(callee, { name: 'eval' }) ||
            t.isIdentifier(callee, { name: 'Function' })) {
          threats.push({
            type: 'DYNAMIC_CODE_EXECUTION',
            message: 'Code uses dynamic code execution',
            package: packageName,
            severity: 'HIGH',
            details: 'Detected eval() or Function() usage which could execute malicious code'
          });
        }
      },
      
      // Detect suspicious string patterns
      StringLiteral(path: any) {
        const value = path.node.value;
        
        // Check for obfuscated patterns (including _0x20669a and similar)
        if (value.match(/^_0x[a-f0-9]+$/i)) {
          if (isNullVoidCode(packageName)) {
            // For NullVoid's own code, this is legitimate security detection patterns
            threats.push({
              type: 'OBFUSCATED_CODE',
              message: 'Code contains obfuscated string patterns (NullVoid security detection)',
              package: packageName,
              severity: 'LOW',
              details: `Detected obfuscated string: ${value} - This is legitimate security detection code in NullVoid, not malicious`
            });
          } else if (isTestFile(packageName)) {
            // For test files, these are legitimate test patterns
            threats.push({
              type: 'OBFUSCATED_CODE',
              message: 'Code contains obfuscated string patterns (test file)',
              package: packageName,
              severity: 'LOW',
              details: `Detected obfuscated string: ${value} - This is legitimate test code, not malicious`
            });
          } else {
            threats.push({
              type: 'OBFUSCATED_CODE',
              message: 'Code contains obfuscated string patterns',
              package: packageName,
              severity: 'HIGH',
              details: `Detected obfuscated string: ${value} - This pattern is associated with recent npm supply chain attacks`
            });
          }
        }
        
        // Check for base64 encoded content
        if (value.length > 100 && /^[A-Za-z0-9+/]+=*$/.test(value)) {
          threats.push({
            type: 'ENCODED_CONTENT',
            message: 'Code contains large base64 encoded strings',
            package: packageName,
            severity: 'MEDIUM',
            details: 'Detected potential base64 encoded malicious content'
          });
        }
      }
    });
    
  } catch (error: any) {
    // If AST parsing fails, it might be obfuscated code
    if (error.message.includes('Unexpected token') || 
        error.message.includes('SyntaxError')) {
      threats.push({
        type: 'OBFUSCATED_CODE',
        message: 'Code appears to be obfuscated or malformed',
        package: packageName,
        severity: 'HIGH',
        details: 'Failed to parse JavaScript AST - possible obfuscation'
      });
    }
  }
  
  return threats;
}