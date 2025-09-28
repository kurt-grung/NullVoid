import { Threat, createThreat } from '../types/core';
import { isNullVoidCode, isTestFile } from './nullvoidDetection';

/**
 * Check if a file is a configuration file
 * @param filePath - File path to check
 * @returns True if it's a config file
 */
export function isConfigFile(filePath: string): boolean {
  if (!filePath) return false;
  
  const fileName = filePath.split('/').pop() || filePath.split('\\').pop() || filePath;
  const configPatterns = [
    '.eslintrc.js',
    '.eslintrc.json',
    '.eslintrc.yaml',
    '.eslintrc.yml',
    'jest.config.js',
    'jest.config.json',
    'webpack.config.js',
    'rollup.config.js',
    'vite.config.js',
    'babel.config.js',
    '.babelrc.js',
    'tsconfig.json',
    'package.json',
    'package-lock.json',
    'yarn.lock',
    'pnpm-lock.yaml',
    '.gitignore',
    '.gitattributes',
    'Dockerfile',
    'docker-compose.yml',
    'docker-compose.yaml',
    '.dockerignore',
    'Makefile',
    'README.md',
    'CHANGELOG.md',
    'LICENSE',
    'CONTRIBUTING.md',
    'SECURITY.md',
    'CODE_OF_CONDUCT.md'
  ];
  
  return configPatterns.includes(fileName) || 
         fileName.startsWith('.') ||
         fileName.endsWith('.config.js') ||
         fileName.endsWith('.config.json') ||
         fileName.endsWith('.config.yaml') ||
         fileName.endsWith('.config.yml') ||
         filePath.includes('node_modules/') ||
         filePath.includes('.git/');
}

/**
 * Main malware detection function that analyzes code content for threats
 * @param content - Code content to analyze
 * @param filePath - Optional file path for context
 * @returns Array of detected threats
 */
export function detectMalware(content: string, filePath?: string): Threat[] {
  const threats: Threat[] = [];
  
  // Skip NullVoid's own code
  if (filePath && isNullVoidCode(filePath)) {
    return threats;
  }
  
  // Analyze code structure for malicious patterns
  const structureAnalysis = analyzeCodeStructure(content, filePath);
  if (structureAnalysis.isMalicious && !isNullVoidCode(filePath || '') && !isTestFile(filePath || '') && !isConfigFile(filePath || '')) {
    let severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'CRITICAL';
    let message = 'Code structure indicates malicious obfuscated content';
    let details = structureAnalysis.reason;

    // Downgrade severity for config files and build scripts
    if (isConfigFile(filePath || '')) {
      severity = 'LOW';
      message = 'Code structure indicates obfuscated content (config file)';
      details = `${structureAnalysis.reason} - This appears to be a configuration file, not malicious`;
    }

    threats.push(createThreat(
      'MALICIOUS_CODE_STRUCTURE',
      message,
      filePath || 'unknown',
      filePath ? filePath.split('/').pop() || 'unknown' : 'unknown',
      severity,
      details,
      {
        confidence: structureAnalysis.confidence / 100,
        ...(structureAnalysis.lineNumber && { lineNumber: structureAnalysis.lineNumber }),
        sampleCode: structureAnalysis.sampleCode
      }
    ));
  }
  
  // Check for suspicious module requires
  const suspiciousModules = ['fs', 'child_process', 'eval', 'vm'];
  for (const module of suspiciousModules) {
    if (content.includes(`require('${module}')`)) {
      let severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
      let message: string;
      let details: string;
      
      if (isNullVoidCode(filePath || '')) {
        // For NullVoid's own code, these are legitimate security tools
        severity = 'LOW';
        message = `Suspicious module require: ${module} (NullVoid security tool)`;
        details = `Code requires module: ${module} - This is legitimate security detection code in NullVoid, not malicious`;
      } else if (isTestFile(filePath || '')) {
        // For test files, these are legitimate test patterns
        severity = 'LOW';
        message = `Suspicious module require: ${module} (test file)`;
        details = `Code requires module: ${module} - This is legitimate test code, not malicious`;
      } else if (isConfigFile(filePath || '')) {
        // For config files, these might be legitimate
        severity = 'LOW';
        message = `Suspicious module require: ${module} (config file)`;
        details = `Code requires module: ${module} - This appears to be a configuration file, not malicious`;
      } else {
        // For real malware, this should be CRITICAL severity
        severity = 'CRITICAL';
        message = `Suspicious module require: ${module}`;
        details = `Code requires suspicious module: ${module}`;
      }
      
      threats.push(createThreat(
        'SUSPICIOUS_MODULE',
        message,
        filePath || 'unknown',
        filePath ? filePath.split('/').pop() || 'unknown' : 'unknown',
        severity,
        details,
        { confidence: 0.9 }
      ));
    }
  }
  
  return threats;
}

/**
 * Analyze code structure for malicious patterns
 * @param code - Code content to analyze
 * @param packageName - Package name for context
 * @returns Analysis result with malicious indicators
 */
function analyzeCodeStructure(code: string, packageName?: string): {
  isMalicious: boolean;
  reason: string;
  confidence: number;
  lineNumber: number | null;
  sampleCode: string;
} {
  const analysis = {
    isMalicious: false,
    reason: '',
    confidence: 0,
    lineNumber: null as number | null,
    sampleCode: ''
  };
  
  // Skip NullVoid's own code
  if (packageName && isNullVoidCode(packageName)) {
    return analysis;
  }
  
  const lines = code.split('\n');
  let threatCount = 0;
  let totalConfidence = 0;
  
  // Pattern 1: Variable name mangling
  const variableManglingPattern = /const\s+[a-z]\d+\s*=\s*[A-Z]\s*,\s*[a-z]\d+\s*=\s*[A-Z]/g;
  const manglingMatches = code.match(variableManglingPattern);
  if (manglingMatches && manglingMatches.length > 0) {
    analysis.isMalicious = true;
    analysis.reason += `Variable name mangling detected (${manglingMatches.length} instances). `;
    threatCount++;
    totalConfidence += 30;
    
    // Find line number and sample
    if (!analysis.lineNumber) {
      for (let i = 0; i < lines.length; i++) {
        if (lines[i]?.match(variableManglingPattern)) {
          analysis.lineNumber = i + 1;
          const cleanLine = lines[i]?.trim() || '';
          analysis.sampleCode = '... ' + cleanLine.substring(0, 60) + '...';
          break;
        }
      }
    }
  }
  
  // Pattern 2: Massive obfuscated code blob
  if (code.length > 5000) {
    analysis.isMalicious = true;
    analysis.reason += `Massive obfuscated code blob detected (${code.length} characters). `;
    threatCount++;
    totalConfidence += 25;
  }
  
  // Pattern 3: Hex encoding arrays
  const hexArrayPattern = /\[(0x[0-9a-fA-F]+,\s*){3,}/g;
  const hexMatches = code.match(hexArrayPattern);
  if (hexMatches && hexMatches.length > 0) {
    analysis.isMalicious = true;
    analysis.reason += `Hex encoding arrays detected (${hexMatches.length} instances). `;
    threatCount++;
    totalConfidence += 20;
  }
  
  // Pattern 4: Code appended to legitimate module.exports
  const moduleExportPattern = /module\.exports\s*=\s*[^;]+;\s*const\s+[a-z]\d+\s*=\s*[A-Z]/g;
  const moduleExportMatches = code.match(moduleExportPattern);
  if (moduleExportMatches && moduleExportMatches.length > 0) {
    analysis.isMalicious = true;
    analysis.reason += `Code appended to legitimate module.exports detected. `;
    threatCount++;
    totalConfidence += 35;
    
    // Find line number and sample
    if (!analysis.lineNumber) {
      for (let i = 0; i < lines.length; i++) {
        if (lines[i]?.match(moduleExportPattern)) {
          analysis.lineNumber = i + 1;
          const cleanLine = lines[i]?.trim() || '';
          analysis.sampleCode = '... ' + cleanLine.substring(0, 60) + '...';
          break;
        }
      }
    }
  }
  
  // Pattern 5: High entropy detection
  const entropy = calculateShannonEntropy(code);
  if (entropy > 4.5) {
    analysis.isMalicious = true;
    analysis.reason += `High entropy detected (${entropy.toFixed(2)}). `;
    threatCount++;
    totalConfidence += 15;
  }
  
  // Calculate final confidence
  if (analysis.isMalicious) {
    analysis.confidence = Math.min(totalConfidence, 150); // Cap at 150%
    analysis.reason = `MALICIOUS CODE DETECTED: ${analysis.reason}Confidence: ${analysis.confidence}% (${threatCount} threats)`;
  }
  
  return analysis;
}

/**
 * Calculate Shannon entropy of text
 * @param text - Text to analyze
 * @returns Entropy value
 */
function calculateShannonEntropy(text: string): number {
  if (!text || text.length === 0) return 0;
  
  const frequencies: Record<string, number> = {};
  for (const char of text) {
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  
  let entropy = 0;
  const length = text.length;
  
  for (const count of Object.values(frequencies)) {
    const probability = count / length;
    entropy -= probability * Math.log2(probability);
  }
  
  return entropy;
}