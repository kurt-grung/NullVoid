import { Threat, createThreat } from '../types/core';
import { isNullVoidCode, isTestFile } from './nullvoidDetection';
import { DETECTION_PATTERNS } from './config';

/**
 * Check if a file is a configuration file
 * @param filePath - File path to check
 * @returns True if it's a config file
 */
export function isConfigFile(filePath: string): boolean {
  if (!filePath) return false;
  
  const fileName = filePath.split('/').pop() || filePath.split('\\').pop() || filePath;
  
  // Check against centralized config patterns
  return DETECTION_PATTERNS.CONFIG_FILE_PATTERNS.includes(fileName) || 
         DETECTION_PATTERNS.DOT_FILE_PATTERNS.includes(fileName) ||
         fileName.startsWith('.') ||
         DETECTION_PATTERNS.CONFIG_EXTENSIONS.some(ext => fileName.endsWith(ext)) ||
         DETECTION_PATTERNS.EXCLUDED_DIRECTORIES.some(dir => filePath.includes(dir)) ||
         DETECTION_PATTERNS.GRAPHICS_FILE_PATTERNS.some(pattern => fileName.includes(pattern));
}

/**
 * Check if content is legitimate graphics/shaders code based on structure analysis
 * @param content - Code content to analyze
 * @param filePath - Optional file path for context
 * @returns True if this appears to be legitimate graphics code
 */
function isUtilityFunction(content: string): boolean {
  const utilityPatterns = DETECTION_PATTERNS.UTILITY_FUNCTION_PATTERNS;
  let utilityPatternCount = 0;
  
  for (const pattern of utilityPatterns) {
    const matches = content.match(pattern);
    if (matches) {
      utilityPatternCount += matches.length;
    }
  }
  
  // If we find multiple utility function patterns, it's likely legitimate utility code
  return utilityPatternCount >= 3;
}

function isServerCode(content: string): boolean {
  const serverPatterns = DETECTION_PATTERNS.SERVER_PATTERNS;
  let serverPatternCount = 0;
  
  for (const pattern of serverPatterns) {
    const matches = content.match(pattern);
    if (matches) {
      serverPatternCount += matches.length;
    }
  }
  
  // If we find multiple server patterns, it's likely legitimate server code
  return serverPatternCount >= 5;
}

function isReactTestingCode(content: string): boolean {
  const testingPatterns = DETECTION_PATTERNS.REACT_TESTING_PATTERNS;
  let testingPatternCount = 0;
  
  for (const pattern of testingPatterns) {
    const matches = content.match(pattern);
    if (matches) {
      testingPatternCount += matches.length;
    }
  }
  
  // If we find testing patterns, it's likely legitimate testing code
  return testingPatternCount >= 2;
}

function isBlockchainCode(content: string): boolean {
  const blockchainPatterns = DETECTION_PATTERNS.BLOCKCHAIN_PATTERNS;
  let blockchainPatternCount = 0;
  
  for (const pattern of blockchainPatterns) {
    const matches = content.match(pattern);
    if (matches) {
      blockchainPatternCount += matches.length;
    }
  }
  
  // If we find blockchain patterns, it's likely legitimate blockchain code
  return blockchainPatternCount >= 2;
}

function isSocketEventMapping(content: string): boolean {
  const socketPatterns = DETECTION_PATTERNS.SOCKET_EVENT_PATTERNS;
  let socketPatternCount = 0;
  
  for (const pattern of socketPatterns) {
    const matches = content.match(pattern);
    if (matches) {
      socketPatternCount += matches.length;
    }
  }
  
  // If we find multiple socket event patterns, it's likely a legitimate mapping
  return socketPatternCount >= 3;
}

function isGraphicsLibraryCode(content: string): boolean {
  // Check for shader code structure - this is the most reliable indicator
  if (isShaderCode(content)) {
    return true;
  }
  
  // Check for Three.js/webgl framework usage patterns
  if (isWebGLFrameworkCode(content)) {
    return true;
  }
  
  // Check for legitimate graphics library imports
  if (hasLegitimateGraphicsImports(content)) {
    return true;
  }
  
  // Check for React/JSX framework code
  if (isReactFrameworkCode(content)) {
    return true;
  }
  
  return false;
}

/**
 * Detect if content contains legitimate shader code
 * @param content - Code content to analyze
 * @returns True if this is legitimate shader code
 */
function isShaderCode(content: string): boolean {
  // Look for GLSL shader patterns
  const shaderPatterns = DETECTION_PATTERNS.SHADER_PATTERNS;
  
  let shaderPatternCount = 0;
  for (const pattern of shaderPatterns) {
    const matches = content.match(pattern);
    if (matches) {
      shaderPatternCount += matches.length;
    }
  }
  
  // If we find multiple shader patterns, likely legitimate shader code
  if (shaderPatternCount >= 3) {
    return true;
  }
  
  // Check for shader code blocks (strings containing GLSL)
  const shaderStringPattern = DETECTION_PATTERNS.SHADER_STRING_PATTERN;
  const shaderStrings = content.match(shaderStringPattern);
  if (shaderStrings && shaderStrings.length >= 2) {
    return true;
  }
  
  return false;
}

/**
 * Detect if content uses legitimate WebGL/graphics frameworks
 * @param content - Code content to analyze
 * @returns True if this uses legitimate graphics frameworks
 */
function isWebGLFrameworkCode(content: string): boolean {
  // Check for Three.js specific patterns that indicate legitimate usage
  const threeJSPatterns = DETECTION_PATTERNS.THREE_JS_PATTERNS;
  
  let threeJSPatternCount = 0;
  for (const pattern of threeJSPatterns) {
    const matches = content.match(pattern);
    if (matches) {
      threeJSPatternCount += matches.length;
    }
  }
  
  // If we find multiple Three.js patterns, likely legitimate
  if (threeJSPatternCount >= 5) {
    return true;
  }
  
  // Check for other graphics frameworks
  const otherFrameworkPatterns = DETECTION_PATTERNS.OTHER_FRAMEWORK_PATTERNS;
  
  for (const pattern of otherFrameworkPatterns) {
    if (pattern.test(content)) {
      return true;
    }
  }
  
  return false;
}

/**
 * Detect if content uses React/JSX framework
 * @param content - Code content to analyze
 * @returns True if this uses React/JSX framework
 */
function isReactFrameworkCode(content: string): boolean {
  // Check for React imports and usage patterns
  const reactPatterns = DETECTION_PATTERNS.REACT_PATTERNS;
  
  let reactPatternCount = 0;
  for (const pattern of reactPatterns) {
    const matches = content.match(pattern);
    if (matches) {
      reactPatternCount += matches.length;
    }
  }
  
  // If we find multiple React patterns, likely legitimate React code
  if (reactPatternCount >= 3) { // Lowered threshold for simple React components
    return true;
  }
  
  // Check for React-specific imports
  const reactImports = DETECTION_PATTERNS.REACT_IMPORTS;
  
  for (const lib of reactImports) {
    if (content.includes(`from "${lib}"`) || 
        content.includes(`from '${lib}'`) ||
        content.includes(`require('${lib}')`) ||
        content.includes(`require("${lib}")`)) {
      return true;
    }
  }
  
  return false;
}

/**
 * Check for legitimate graphics library imports
 * @param content - Code content to analyze
 * @returns True if has legitimate graphics imports
 */
function hasLegitimateGraphicsImports(content: string): boolean {
  const legitimateImports = DETECTION_PATTERNS.GRAPHICS_IMPORTS;
  
  for (const lib of legitimateImports) {
    if (content.includes(`from "${lib}"`) || 
        content.includes(`from '${lib}'`) ||
        content.includes(`require('${lib}')`) ||
        content.includes(`require("${lib}")`)) {
      return true;
    }
  }
  
  return false;
}

/**
 * Helper function to intelligently detect malware start in a line
 * @param cleanLine - Cleaned line of code
 * @param patterns - Array of regex patterns to check
 * @returns Object with malwareStart index and legitimateEnd index
 */
function detectMalwareStart(cleanLine: string, patterns: RegExp[]): { malwareStart: number; legitimateEnd: number } {
  // First, find where malware patterns start
  let malwareStart = -1;
  for (const pattern of patterns) {
    const match = cleanLine.match(pattern);
    if (match && match.index !== undefined) {
      malwareStart = match.index;
      break;
    }
  }
  
  if (malwareStart === -1) {
    return { malwareStart: -1, legitimateEnd: -1 };
  }
  
  // Now intelligently find where legitimate code ends
  let legitimateEnd = 0;
  
  // Look for specific legitimate code patterns that end before malware
  const legitimatePatterns = DETECTION_PATTERNS.LEGITIMATE_PATTERNS;
  
  // Find the last legitimate pattern before malware starts
  for (const pattern of legitimatePatterns) {
    const match = cleanLine.match(pattern);
    if (match && match.index !== undefined) {
      const endPos = match.index + match[0].length;
      if (endPos <= malwareStart) {
        legitimateEnd = Math.max(legitimateEnd, endPos);
      }
    }
  }
  
  // If we found a legitimate ending, trim whitespace
  if (legitimateEnd > 0) {
    // Skip any whitespace after legitimate code
    while (legitimateEnd < malwareStart && legitimateEnd < cleanLine.length && /\s/.test(cleanLine[legitimateEnd] || '')) {
      legitimateEnd++;
    }
  }
  
  return { malwareStart, legitimateEnd };
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
  
  // Skip legitimate graphics libraries and Three.js code
  if (isGraphicsLibraryCode(content)) {
    return threats;
  }

  // Skip legitimate socket event mappings
  if (isSocketEventMapping(content)) {
    return threats;
  }

  // Skip legitimate utility functions
  if (isUtilityFunction(content)) {
    return threats;
  }

  // Skip legitimate server code
  if (isServerCode(content)) {
    return threats;
  }

  // Skip legitimate React/testing code
  if (isReactTestingCode(content)) {
    return threats;
  }

  // Skip legitimate blockchain code
  if (isBlockchainCode(content)) {
    return threats;
  }
  
  // Analyze code structure for malicious patterns
  const structureAnalysis = analyzeCodeStructure(content, filePath);
  if (structureAnalysis.isMalicious && !isTestFile(filePath || '') && !isConfigFile(filePath || '')) {
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
  const suspiciousModules = DETECTION_PATTERNS.SUSPICIOUS_MODULES;
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
  const variableManglingPattern = DETECTION_PATTERNS.MALWARE_PATTERNS.VARIABLE_MANGLING;
  const manglingMatches = code.match(new RegExp(variableManglingPattern.source, 'g'));
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
          const { malwareStart, legitimateEnd } = detectMalwareStart(cleanLine, [variableManglingPattern]);
          
          if (malwareStart !== -1) {
            // Show only the malicious part, intelligently removing legitimate code
            if (legitimateEnd > 0 && legitimateEnd <= malwareStart) {
              // Show malicious part only, with ... prefix to indicate removed legitimate code
              const attackPart = cleanLine.substring(malwareStart, malwareStart + 60);
              analysis.sampleCode = '... ' + attackPart + '...';
            } else {
              // Fallback: show the line without excessive whitespace
              analysis.sampleCode = cleanLine.substring(0, 80) + (cleanLine.length > 80 ? '...' : '');
            }
          } else {
            analysis.sampleCode = cleanLine.substring(0, 80) + (cleanLine.length > 80 ? '...' : '');
          }
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
    
    // Find line number and sample for massive code blob
    if (!analysis.lineNumber) {
      // Look for the largest line in the code as likely obfuscated content
      let maxLineLength = 0;
      let maxLineIndex = 0;
      for (let i = 0; i < lines.length; i++) {
        const lineLength = lines[i]?.length || 0;
        if (lineLength > maxLineLength) {
          maxLineLength = lineLength;
          maxLineIndex = i;
        }
      }
      if (maxLineLength > 200) { // Only if line is suspiciously long
        analysis.lineNumber = maxLineIndex + 1;
        const cleanLine = lines[maxLineIndex]?.trim() || '';
        
        // Try to extract malicious part using detectMalwareStart
        const { malwareStart, legitimateEnd } = detectMalwareStart(cleanLine, [variableManglingPattern]);
        
        if (malwareStart !== -1) {
          // Show only the malicious part, intelligently removing legitimate code
          if (legitimateEnd > 0 && legitimateEnd <= malwareStart) {
            // Show malicious part only, with ... prefix to indicate removed legitimate code
            const attackPart = cleanLine.substring(malwareStart, malwareStart + 60);
            analysis.sampleCode = '... ' + attackPart + '...';
          } else {
            // Fallback: show the line without excessive whitespace
            analysis.sampleCode = cleanLine.substring(0, 80) + (cleanLine.length > 80 ? '...' : '');
          }
        } else {
          analysis.sampleCode = '... ' + cleanLine.substring(0, 60) + '...';
        }
      }
    }
  }
  
  // Pattern 3: Hex encoding arrays
  const hexArrayPattern = DETECTION_PATTERNS.MALWARE_PATTERNS.HEX_ARRAYS;
  const hexMatches = code.match(hexArrayPattern);
  if (hexMatches && hexMatches.length > 0) {
    analysis.isMalicious = true;
    analysis.reason += `Hex encoding arrays detected (${hexMatches.length} instances). `;
    threatCount++;
    totalConfidence += 20;
    
    // Find line number and sample for hex arrays
    if (!analysis.lineNumber) {
      for (let i = 0; i < lines.length; i++) {
        if (lines[i]?.match(hexArrayPattern)) {
          analysis.lineNumber = i + 1;
          const cleanLine = lines[i]?.trim() || '';
          analysis.sampleCode = '... ' + cleanLine.substring(0, 60) + '...';
          break;
        }
      }
    }
  }
  
  // Pattern 4: Code appended to legitimate module.exports
  const moduleExportPattern = DETECTION_PATTERNS.MALWARE_PATTERNS.MODULE_EXPORT_MALICIOUS;
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
          
          // Find where module.exports ends and malicious code begins
          const moduleExportMatch = cleanLine.match(/module\.exports\s*=\s*[^;]+;\s*/);
          if (moduleExportMatch && moduleExportMatch.index !== undefined) {
            const moduleExportEnd = moduleExportMatch.index + moduleExportMatch[0].length;
            const afterModuleExport = cleanLine.substring(moduleExportEnd);
            const { malwareStart: relativeMalwareStart } = detectMalwareStart(afterModuleExport, [variableManglingPattern]);
            if (relativeMalwareStart !== -1) {
              const malwareStart = moduleExportEnd + relativeMalwareStart;
              const attackPart = cleanLine.substring(malwareStart, malwareStart + 60);
              analysis.sampleCode = '... ' + attackPart + '...';
            } else {
              analysis.sampleCode = cleanLine.substring(0, 80) + (cleanLine.length > 80 ? '...' : '');
            }
          } else {
            analysis.sampleCode = cleanLine.substring(0, 80) + (cleanLine.length > 80 ? '...' : '');
          }
          break;
        }
      }
    }
  }
  
  // Pattern 5: High entropy detection
  const entropy = calculateShannonEntropy(code);
  const entropyThreshold = isReactFrameworkCode(code) ? 5.0 : 4.5; // Higher threshold for React files
  
  if (entropy > entropyThreshold) {
    analysis.isMalicious = true;
    analysis.reason += `High entropy detected (${entropy.toFixed(2)}). `;
    threatCount++;
    totalConfidence += 15;
    
    // Find line number and sample for high entropy content
    if (!analysis.lineNumber) {
      // Look for lines with high entropy (likely obfuscated)
      let maxEntropy = 0;
      let maxEntropyLineIndex = 0;
      for (let i = 0; i < lines.length; i++) {
        const lineEntropy = calculateShannonEntropy(lines[i] || '');
        if (lineEntropy > maxEntropy && lineEntropy > 4.0) {
          maxEntropy = lineEntropy;
          maxEntropyLineIndex = i;
        }
      }
      if (maxEntropy > 4.0) {
        analysis.lineNumber = maxEntropyLineIndex + 1;
        const cleanLine = lines[maxEntropyLineIndex]?.trim() || '';
        analysis.sampleCode = '... ' + cleanLine.substring(0, 60) + '...';
      }
    }
  }
  
  // Calculate final confidence
  if (analysis.isMalicious) {
    analysis.confidence = Math.min(totalConfidence, 150); // Cap at 150%
    analysis.reason = `MALICIOUS CODE DETECTED: ${analysis.reason}Confidence: ${analysis.confidence}% (${threatCount} threats)`;
  }
  
  return analysis;
}

/**
 * Filter threats by severity level
 * @param threats - Array of threats to filter
 * @param showAll - Whether to show all threats or only high severity
 * @returns Filtered array of threats
 */
export function filterThreatsBySeverity(threats: Threat[], showAll: boolean = false): Threat[] {
  if (showAll) {
    return threats;
  }
  
  return threats.filter(threat => 
    threat.severity === 'CRITICAL' || threat.severity === 'HIGH'
  );
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