/**
 * Centralized Malware Detection Utilities
 * Reusable patterns and functions for detecting malicious code
 */

const { isNullVoidCode } = require('./nullvoidDetection');
const { DETECTION_CONFIG } = require('./config');

/**
 * Common malware patterns for intelligent detection
 * Uses centralized configuration for consistency
 */
const MALWARE_PATTERNS = DETECTION_CONFIG.MALWARE_PATTERNS;

/**


/**
 * Helper function to intelligently detect malware start in a line
 * @param {string} cleanLine - Cleaned line of code
 * @param {Array} patterns - Array of regex patterns to check
 * @returns {Object} Object with malwareStart index and legitimateEnd index
 */
function detectMalwareStart(cleanLine, patterns = Object.values(MALWARE_PATTERNS).flat()) {
  // First, find where malware patterns start
  let malwareStart = -1;
  for (const pattern of patterns) {
    const match = cleanLine.match(pattern);
    if (match) {
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
  const legitimatePatterns = DETECTION_CONFIG.LEGITIMATE_PATTERNS;
  
  // Find the last legitimate pattern before malware starts
  for (const pattern of legitimatePatterns) {
    const match = cleanLine.match(pattern);
    if (match) {
      const endPos = match.index + match[0].length;
      if (endPos <= malwareStart) {
        legitimateEnd = Math.max(legitimateEnd, endPos);
      }
    }
  }
  
  // If we found a legitimate ending, trim whitespace
  if (legitimateEnd > 0) {
    // Skip any whitespace after legitimate code
    while (legitimateEnd < malwareStart && /\s/.test(cleanLine[legitimateEnd])) {
      legitimateEnd++;
    }
  }
  
  return { malwareStart, legitimateEnd };
}

/**
 * Analyze code structure for malicious patterns
 * @param {string} code - JavaScript code to analyze
 * @param {string} packageName - Package name for context
 * @returns {Object} Analysis result with isMalicious flag and reason
 */
function analyzeCodeStructure(code, packageName) {
  const analysis = {
    isMalicious: false,
    reason: '',
    confidence: 0,
    lineNumber: null,
    sampleCode: ''
  };
  
  // Skip NullVoid's own code
  if (isNullVoidCode(packageName)) {
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
        if (lines[i].match(variableManglingPattern)) {
          analysis.lineNumber = i + 1;
          const cleanLine = lines[i].trim();
          const { malwareStart, legitimateEnd } = detectMalwareStart(cleanLine, MALWARE_PATTERNS.variableMangling);
          
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
  
  // Pattern 4: Anti-debugging patterns
  const antiDebugPatterns = [
    /debugger\s*;/,                  // debugger statement
    /console\.log\s*=\s*function/,   // console.log override
    /console\.warn\s*=\s*function/,  // console.warn override
    /console\.error\s*=\s*function/  // console.error override
  ];
  
  let antiDebugCount = 0;
  for (const pattern of antiDebugPatterns) {
    const matches = code.match(pattern);
    if (matches) antiDebugCount += matches.length;
  }
  
  if (antiDebugCount > 0) {
    analysis.isMalicious = true;
    analysis.reason += `Anti-debugging patterns detected. `;
    threatCount++;
    totalConfidence += 15;
  }
  
  // Pattern 5: Code appended to legitimate module.exports
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
        if (lines[i].match(moduleExportPattern)) {
          analysis.lineNumber = i + 1;
          const cleanLine = lines[i].trim();
          
          // Find where legitimate code ends and malware begins
          const moduleExportEnd = cleanLine.indexOf(';');
          let malwareStart = -1;
          
          if (moduleExportEnd !== -1) {
            const afterModuleExport = cleanLine.substring(moduleExportEnd + 1);
            const { malwareStart: relativeMalwareStart, legitimateEnd } = detectMalwareStart(afterModuleExport, MALWARE_PATTERNS.variableMangling);
            if (relativeMalwareStart !== -1) {
              malwareStart = moduleExportEnd + 1 + relativeMalwareStart;
            }
          }
          
          if (malwareStart !== -1) {
            // Show only the malicious part, intelligently removing legitimate code
            const attackPart = cleanLine.substring(malwareStart, malwareStart + 60);
            analysis.sampleCode = '... ' + attackPart + '...';
          } else {
            analysis.sampleCode = cleanLine.substring(0, 80) + (cleanLine.length > 80 ? '...' : '');
          }
          break;
        }
      }
    }
  }
  
  // Pattern 6: High entropy detection
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
    analysis.reason = `MALICIOUS CODE DETECTED: ${analysis.reason}Confidence: ${analysis.confidence}%`;
  }
  
  return analysis;
}

/**
 * Calculate Shannon entropy of text
 * @param {string} text - Text to analyze
 * @returns {number} Entropy value
 */
function calculateShannonEntropy(text) {
  if (!text || text.length === 0) return 0;
  
  const frequencies = {};
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

/**
 * Detect wallet hijacking patterns
 * @param {string} content - Code content to analyze
 * @param {string} packageName - Package name for context
 * @returns {Array} Array of detected threats
 */
function detectWalletHijacking(content, packageName) {
  const threats = [];
  
  if (isNullVoidCode(packageName)) {
    return threats;
  }
  
  for (const pattern of MALWARE_PATTERNS.walletHijacking) {
    const matches = content.match(pattern);
    if (matches) {
      threats.push({
        type: 'WALLET_HIJACKING',
        severity: 'CRITICAL',
        message: 'Wallet hijacking pattern detected',
        package: packageName,
        details: `Detected pattern: ${pattern.source}`,
        confidence: 90
      });
    }
  }
  
  return threats;
}

/**
 * Detect obfuscated IoCs (Indicators of Compromise)
 * @param {string} content - Code content to analyze
 * @param {string} packageName - Package name for context
 * @returns {Array} Array of detected threats
 */
function detectObfuscatedIoCs(content, packageName) {
  const threats = [];
  
  if (isNullVoidCode(packageName)) {
    return threats;
  }
  
  // Known obfuscated patterns from recent npm attacks
  const obfuscatedPatterns = [
    '_0x112fa8',
    'stealthProxyControl',
    'runmask',
    'newdlocal',
    'window.ethereum',
    'ethereum.request'
  ];
  
  for (const pattern of obfuscatedPatterns) {
    if (content.includes(pattern)) {
      threats.push({
        type: 'OBFUSCATED_IOC',
        severity: 'LOW',
        message: `Known obfuscated IoC detected: ${pattern}`,
        package: packageName,
        details: `Pattern '${pattern}' matches known malicious obfuscation techniques`
      });
    }
  }
  
  return threats;
}

/**
 * Detect dynamic requires and suspicious module loading
 * @param {string} code - Code to analyze
 * @param {string} packageName - Package name for context
 * @returns {Array} Array of detected threats
 */
function detectDynamicRequires(code, packageName) {
  const threats = [];
  
  if (isNullVoidCode(packageName)) {
    return threats;
  }
  
  // Check for suspicious modules
  const suspiciousModules = ['fs', 'child_process', 'os', 'crypto', 'net', 'http'];
  
  for (const module of suspiciousModules) {
    const requirePattern = new RegExp(`require\\s*\\(\\s*['"\`]${module}['"\`]\\s*\\)`, 'g');
    const matches = code.match(requirePattern);
    
    if (matches) {
      const severity = isTestFile(packageName) ? 'LOW' : 'CRITICAL';
      threats.push({
        type: 'SUSPICIOUS_MODULE',
        severity: severity,
        message: `Suspicious module require: ${module}`,
        package: packageName,
        details: `Code requires suspicious module: ${module}`
      });
    }
  }
  
  // Check for dynamic requires
  for (const pattern of MALWARE_PATTERNS.dynamicRequires) {
    const matches = code.match(pattern);
    if (matches) {
      threats.push({
        type: 'DYNAMIC_REQUIRE',
        severity: 'HIGH',
        message: 'Dynamic module loading detected',
        package: packageName,
        details: 'Code uses dynamic require() or import() - potential security risk'
      });
    }
  }
  
  return threats;
}

/**
 * Check if package is a test file
 * @param {string} packageName - Package name to check
 * @returns {boolean} True if test file
 */
function isTestFile(packageName) {
  if (!packageName) return false;
  
  return packageName.includes('test') || 
         packageName.includes('spec') || 
         packageName.includes('__tests__') ||
         packageName.startsWith('test-') ||
         packageName.startsWith('test_');
}

module.exports = {
  MALWARE_PATTERNS,
  detectMalwareStart,
  analyzeCodeStructure,
  calculateShannonEntropy,
  detectWalletHijacking,
  detectObfuscatedIoCs,
  detectDynamicRequires,
  isTestFile
};
