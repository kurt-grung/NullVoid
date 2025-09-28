/**
 * Dependency Confusion Detection Module
 * 
 * Detects potential dependency confusion attacks by analyzing:
 * - Git history vs npm registry creation dates
 * - Scope ownership and namespace conflicts
 * - Package name similarity patterns
 * - Timeline-based threat indicators
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const https = require('https');
const { promisify } = require('util');
const { DEPENDENCY_CONFUSION_CONFIG } = require('./config');

/**
 * Calculate string similarity using Levenshtein distance
 * @param {string} str1 - First string
 * @param {string} str2 - Second string
 * @returns {number} Similarity score (0-1)
 */
function calculateSimilarity(str1, str2) {
  const longer = str1.length > str2.length ? str1 : str2;
  const shorter = str1.length > str2.length ? str2 : str1;
  
  if (longer.length === 0) return 1.0;
  
  const distance = levenshteinDistance(longer, shorter);
  return (longer.length - distance) / longer.length;
}

/**
 * Calculate Levenshtein distance between two strings
 * @param {string} str1 - First string
 * @param {string} str2 - Second string
 * @returns {number} Edit distance
 */
function levenshteinDistance(str1, str2) {
  const matrix = [];
  
  for (let i = 0; i <= str2.length; i++) {
    matrix[i] = [i];
  }
  
  for (let j = 0; j <= str1.length; j++) {
    matrix[0][j] = j;
  }
  
  for (let i = 1; i <= str2.length; i++) {
    for (let j = 1; j <= str1.length; j++) {
      if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }
  
  return matrix[str2.length][str1.length];
}

/**
 * Get package creation date from npm registry
 * @param {string} packageName - Package name
 * @returns {Promise<Date|null>} Creation date or null
 */
async function getPackageCreationDate(packageName) {
  return new Promise((resolve) => {
    const url = `${DEPENDENCY_CONFUSION_CONFIG.REGISTRY_ENDPOINTS.npm}/${packageName}`;
    
    const request = https.get(url, (response) => {
      let data = '';
      
      response.on('data', (chunk) => {
        data += chunk;
      });
      
      response.on('end', () => {
        try {
          const packageData = JSON.parse(data);
          if (packageData.time && packageData.time.created) {
            resolve(new Date(packageData.time.created));
          } else {
            resolve(null);
          }
        } catch (error) {
          resolve(null);
        }
      });
    });
    
    request.on('error', () => {
      resolve(null);
    });
    
    request.setTimeout(5000, () => {
      request.destroy();
      resolve(null);
    });
  });
}

/**
 * Get git history for a package/directory
 * @param {string} packagePath - Path to package
 * @returns {Object} Git history information
 */
function getGitHistory(packagePath) {
  try {
    // Get first commit date
    const firstCommit = execSync(
      `git log --reverse --format="%H %ci" -- "${packagePath}" | head -1`,
      { cwd: packagePath, encoding: 'utf8', timeout: 10000 }
    ).trim();
    
    if (!firstCommit) return null;
    
    const [hash, dateStr] = firstCommit.split(' ');
    const firstCommitDate = new Date(dateStr);
    
    // Get recent commits
    const recentCommits = execSync(
      `git log --format="%ci" --since="1 year ago" -- "${packagePath}" | wc -l`,
      { cwd: packagePath, encoding: 'utf8', timeout: 5000 }
    ).trim();
    
    return {
      firstCommitDate,
      recentCommitCount: parseInt(recentCommits) || 0,
      hasGitHistory: true
    };
  } catch (error) {
    return {
      hasGitHistory: false,
      error: error.message
    };
  }
}

/**
 * Analyze package name for suspicious patterns
 * @param {string} packageName - Package name to analyze
 * @returns {Object} Analysis results
 */
function analyzePackageName(packageName) {
  const analysis = {
    isScoped: packageName.startsWith('@'),
    scope: null,
    unscopedName: packageName,
    suspiciousPatterns: [],
    similarityScore: 0,
    riskLevel: 'LOW'
  };
  
  // Extract scope if present
  if (analysis.isScoped) {
    const scopeMatch = packageName.match(/^@([^/]+)\/(.+)$/);
    if (scopeMatch) {
      analysis.scope = scopeMatch[1];
      analysis.unscopedName = scopeMatch[2];
    }
  }
  
  // Check for suspicious patterns
  for (const pattern of DEPENDENCY_CONFUSION_CONFIG.SUSPICIOUS_NAME_PATTERNS) {
    if (pattern.test(analysis.unscopedName)) {
      analysis.suspiciousPatterns.push(pattern.toString());
    }
  }
  
  // Check scope type
  if (analysis.scope) {
    if (DEPENDENCY_CONFUSION_CONFIG.SCOPE_PATTERNS.PRIVATE_SCOPES.includes(`@${analysis.scope}`)) {
      analysis.scopeType = 'PRIVATE';
      analysis.riskLevel = 'HIGH';
    } else if (DEPENDENCY_CONFUSION_CONFIG.SCOPE_PATTERNS.PUBLIC_SCOPES.includes(`@${analysis.scope}`)) {
      analysis.scopeType = 'PUBLIC';
    } else {
      analysis.scopeType = 'UNKNOWN';
      analysis.riskLevel = 'MEDIUM';
    }
  }
  
  return analysis;
}

/**
 * Detect dependency confusion threats
 * @param {string} packageName - Package name to analyze
 * @param {string} packagePath - Path to package directory
 * @returns {Promise<Array>} Array of detected threats
 */
async function detectDependencyConfusion(packageName, packagePath) {
  const threats = [];
  
  try {
    // Get package creation date from npm registry
    const creationDate = await getPackageCreationDate(packageName);
    if (!creationDate) {
      return threats; // Skip if we can't get registry data
    }
    
    // Get git history
    const gitHistory = getGitHistory(packagePath);
    if (!gitHistory || !gitHistory.hasGitHistory) {
      return threats; // Skip if no git history
    }
    
    // Analyze package name
    const nameAnalysis = analyzePackageName(packageName);
    
    // Calculate timeline risk
    const daysDifference = Math.abs(creationDate - gitHistory.firstCommitDate) / (1000 * 60 * 60 * 24);
    
    let timelineRisk = 'LOW';
    if (daysDifference <= DEPENDENCY_CONFUSION_CONFIG.TIMELINE_THRESHOLDS.CRITICAL) {
      timelineRisk = 'CRITICAL';
    } else if (daysDifference <= DEPENDENCY_CONFUSION_CONFIG.TIMELINE_THRESHOLDS.HIGH_RISK) {
      timelineRisk = 'HIGH';
    } else if (daysDifference <= DEPENDENCY_CONFUSION_CONFIG.TIMELINE_THRESHOLDS.SUSPICIOUS) {
      timelineRisk = 'MEDIUM';
    }
    
    // Generate threats based on analysis
    if (timelineRisk !== 'LOW') {
      threats.push({
        type: 'DEPENDENCY_CONFUSION_TIMELINE',
        message: `Package creation date suspiciously close to git history (${Math.round(daysDifference)} days)`,
        severity: timelineRisk === 'CRITICAL' ? 'CRITICAL' : 
                 timelineRisk === 'HIGH' ? 'HIGH' : 'MEDIUM',
        package: packageName,
        details: `Package created: ${creationDate.toISOString()}, First git commit: ${gitHistory.firstCommitDate.toISOString()}`,
        confidence: Math.min(95, 60 + (30 - daysDifference) * 2),
        properties: {
          creationDate: creationDate.toISOString(),
          firstCommitDate: gitHistory.firstCommitDate.toISOString(),
          daysDifference: Math.round(daysDifference),
          timelineRisk
        }
      });
    }
    
    // Check for suspicious package name patterns
    if (nameAnalysis.suspiciousPatterns.length > 0) {
      threats.push({
        type: 'DEPENDENCY_CONFUSION_PATTERN',
        message: `Package name follows suspicious naming patterns`,
        severity: nameAnalysis.scopeType === 'PRIVATE' ? 'HIGH' : 'MEDIUM',
        package: packageName,
        details: `Suspicious patterns: ${nameAnalysis.suspiciousPatterns.join(', ')}`,
        confidence: 75,
        properties: {
          suspiciousPatterns: nameAnalysis.suspiciousPatterns,
          scopeType: nameAnalysis.scopeType,
          isScoped: nameAnalysis.isScoped
        }
      });
    }
    
    // Check for private scope conflicts
    if (nameAnalysis.scopeType === 'PRIVATE') {
      threats.push({
        type: 'DEPENDENCY_CONFUSION_SCOPE',
        message: `Private scope package may be vulnerable to dependency confusion`,
        severity: 'HIGH',
        package: packageName,
        details: `Private scope '@${nameAnalysis.scope}' detected. Ensure proper npm registry configuration.`,
        confidence: 85,
        properties: {
          scope: nameAnalysis.scope,
          scopeType: nameAnalysis.scopeType,
          unscopedName: nameAnalysis.unscopedName
        }
      });
    }
    
    // Check for low git activity (potential typosquatting)
    if (gitHistory.recentCommitCount < 5 && daysDifference > 30) {
      threats.push({
        type: 'DEPENDENCY_CONFUSION_ACTIVITY',
        message: `Low git activity may indicate typosquatting or abandoned package`,
        severity: 'MEDIUM',
        package: packageName,
        details: `Only ${gitHistory.recentCommitCount} commits in the last year`,
        confidence: 60,
        properties: {
          recentCommitCount: gitHistory.recentCommitCount,
          daysDifference: Math.round(daysDifference)
        }
      });
    }
    
  } catch (error) {
    // Add error as low-priority threat for debugging
    threats.push({
      type: 'DEPENDENCY_CONFUSION_ERROR',
      message: `Error analyzing dependency confusion: ${error.message}`,
      severity: 'LOW',
      package: packageName,
      details: error.stack,
      confidence: 10,
      properties: {
        error: error.message,
        stack: error.stack
      }
    });
  }
  
  return threats;
}

/**
 * Analyze multiple packages for dependency confusion
 * @param {Array} packages - Array of package information
 * @returns {Promise<Array>} Combined threats from all packages
 */
async function analyzeDependencyConfusion(packages) {
  const allThreats = [];
  
  for (const pkg of packages) {
    if (pkg.name && pkg.path) {
      const threats = await detectDependencyConfusion(pkg.name, pkg.path);
      allThreats.push(...threats);
    }
  }
  
  return allThreats;
}

module.exports = {
  detectDependencyConfusion,
  analyzeDependencyConfusion,
  analyzePackageName,
  getPackageCreationDate,
  getGitHistory,
  calculateSimilarity,
  DEPENDENCY_CONFUSION_CONFIG
};
