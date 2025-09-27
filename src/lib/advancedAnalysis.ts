/**
 * Advanced Analysis Functions
 * Migrated from scan.js for comprehensive package analysis
 */

import fs from 'fs';
import path from 'path';
import https from 'https';
import { execSync } from 'child_process';
import { Threat } from '../types/core';
import { POPULAR_FRAMEWORKS } from './config';

/**
 * Analyze dependency tree for suspicious patterns
 */
export function analyzeDependencyTree(tree: Record<string, any>): Threat[] {
  const threats: Threat[] = [];
  
  // Analyze tree structure for suspicious patterns
  const suspiciousPackages: string[] = [];
  const deepDependencies: Array<{name: string, depth: number, threatCount: number}> = [];
  
  for (const [packageName, packageInfo] of Object.entries(tree)) {
    // Check for suspicious package names
    if (packageName.match(/^[a-z0-9]{32,}$/) || // Random-looking names
        packageName.includes('malware') ||
        packageName.includes('virus') ||
        packageName.includes('trojan') ||
        packageName.includes('backdoor')) {
      suspiciousPackages.push(packageName);
    }
    
    // Check for deep dependency chains (potential hiding spots)
    if (packageInfo.depth >= 2) {
      deepDependencies.push({
        name: packageName,
        depth: packageInfo.depth,
        threatCount: packageInfo.threats?.length || 0
      });
    }
    
    // Check for packages with many transitive dependencies (potential attack vectors)
    const depCount = packageInfo.dependencies ? Object.keys(packageInfo.dependencies).length : 0;
    
    // Higher thresholds for popular frameworks and libraries
    const isPopularFramework = POPULAR_FRAMEWORKS.some((framework: string) => 
      packageName.toLowerCase().includes(framework)
    );
    
    const threshold = isPopularFramework ? 60 : 40; // Even higher thresholds to reduce false positives
    
    if (depCount > threshold) {
      threats.push({
        type: 'HIGH_DEPENDENCY_COUNT',
        message: `Package has unusually high number of dependencies (${depCount})`,
        package: packageName,
        severity: 'MEDIUM',
        details: `Package "${packageName}" has ${depCount} dependencies, which could be used to hide malicious code`
      });
    }
  }
  
  // Report suspicious package names
  for (const packageName of suspiciousPackages) {
    threats.push({
      type: 'SUSPICIOUS_PACKAGE_NAME',
      message: `Suspicious package name detected`,
      package: packageName,
      severity: 'HIGH',
      details: `Package name "${packageName}" contains suspicious keywords or patterns`
    });
  }
  
  // Report deep dependencies with threats
  for (const dep of deepDependencies) {
    if (dep.threatCount > 0) {
      threats.push({
        type: 'DEEP_DEPENDENCY_THREAT',
        message: `Deep dependency with threats detected`,
        package: dep.name,
        severity: 'MEDIUM',
        details: `Package "${dep.name}" is a deep dependency (depth ${dep.depth}) with ${dep.threatCount} threats`
      });
    }
  }
  
  return threats;
}

/**
 * Analyze package tarball for malicious content
 */
export async function analyzePackageTarball(packageData: any): Promise<Threat[]> {
  const threats: Threat[] = [];
  let tempDir: string | null = null;
  
  try {
    // Get tarball URL
    const tarballUrl = packageData.dist?.tarball;
    if (!tarballUrl) {
      return threats;
    }
    
    // Create temporary directory
    tempDir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'nullvoid-'));
    
    // Download tarball
    const tarballPath = path.join(tempDir, 'package.tgz');
    await downloadFile(tarballUrl, tarballPath);
    
    // Extract tarball
    execSync(`tar -xzf "${tarballPath}" -C "${tempDir}"`, { stdio: 'pipe' });
    
    // Analyze extracted files
    const extractedDir = path.join(tempDir, 'package');
    if (fs.existsSync(extractedDir)) {
      const fileThreats = await analyzeExtractedFiles(extractedDir);
      threats.push(...fileThreats);
    }
    
  } catch (error: any) {
    threats.push({
      type: 'TARBALL_ANALYSIS_ERROR',
      message: 'Failed to analyze package tarball',
      package: packageData.name || 'unknown',
      severity: 'LOW',
      details: `Tarball analysis failed: ${error.message}`
    });
  } finally {
    // Cleanup
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  }
  
  return threats;
}

/**
 * Analyze package.json for suspicious metadata
 */
export function analyzePackageJson(packageData: any, packageName: string): Threat[] {
  const threats: Threat[] = [];
  
  try {
    // Check scripts for suspicious commands
    if (packageData.scripts) {
      for (const [scriptName, scriptContent] of Object.entries(packageData.scripts)) {
        const script = scriptContent as string;
        
        // Check for suspicious commands
        const suspiciousCommands = [
          'rm -rf',
          'curl',
          'wget',
          'nc ',
          'netcat',
          'python -c',
          'node -e',
          'eval(',
          'base64 -d'
        ];
        
        for (const cmd of suspiciousCommands) {
          if (script.toLowerCase().includes(cmd)) {
            threats.push({
              type: 'SUSPICIOUS_SCRIPT',
              message: `Suspicious command in ${scriptName} script`,
              package: packageName,
              severity: 'HIGH',
              details: `Script "${scriptName}" contains suspicious command: ${cmd}`
            });
          }
        }
      }
    }
    
    // Check for suspicious keywords in description
    if (packageData.description) {
      const suspiciousKeywords = ['malware', 'virus', 'trojan', 'backdoor', 'keylogger'];
      const description = packageData.description.toLowerCase();
      
      for (const keyword of suspiciousKeywords) {
        if (description.includes(keyword)) {
          threats.push({
            type: 'SUSPICIOUS_DESCRIPTION',
            message: 'Suspicious keyword in package description',
            package: packageName,
            severity: 'HIGH',
            details: `Package description contains suspicious keyword: ${keyword}`
          });
        }
      }
    }
    
    // Check for missing or suspicious repository
    if (!packageData.repository || 
        (packageData.repository.url && packageData.repository.url.includes('github.com/user/repo'))) {
      threats.push({
        type: 'MISSING_REPOSITORY',
        message: 'Package missing or suspicious repository information',
        package: packageName,
        severity: 'MEDIUM',
        details: 'Package lacks proper repository information'
      });
    }
    
  } catch (error: any) {
    threats.push({
      type: 'PACKAGE_JSON_ANALYSIS_ERROR',
      message: 'Failed to analyze package.json',
      package: packageName,
      severity: 'LOW',
      details: `Package.json analysis failed: ${error.message}`
    });
  }
  
  return threats;
}

/**
 * Analyze file system usage context
 */
export function analyzeFsUsageContext(code: string, filePath: string): Threat[] {
  const threats: Threat[] = [];
  
  try {
    // Check for suspicious file operations
    const suspiciousPatterns = [
      /fs\.writeFileSync\s*\(\s*['"`][^'"`]*\.(exe|bat|cmd|sh|ps1)['"`]/gi,
      /fs\.writeFileSync\s*\(\s*['"`][^'"`]*\.(key|pem|crt|p12)['"`]/gi,
      /fs\.readFileSync\s*\(\s*['"`][^'"`]*\.(key|pem|crt|p12)['"`]/gi,
      /fs\.unlinkSync\s*\(\s*['"`][^'"`]*\.(log|tmp|temp)['"`]/gi
    ];
    
    for (const pattern of suspiciousPatterns) {
      const matches = code.match(pattern);
      if (matches) {
        threats.push({
          type: 'SUSPICIOUS_FS_OPERATION',
          message: 'Suspicious file system operation detected',
          package: filePath,
          severity: 'HIGH',
          details: `Suspicious file operation: ${matches[0]}`
        });
      }
    }
    
    // Check for path traversal attempts
    const pathTraversalPatterns = [
      /\.\.\/\.\.\//g,
      /\.\.\\\.\.\\/g,
      /\.\.%2f\.\.%2f/gi,
      /\.\.%5c\.\.%5c/gi
    ];
    
    for (const pattern of pathTraversalPatterns) {
      if (pattern.test(code)) {
        threats.push({
          type: 'PATH_TRAVERSAL',
          message: 'Potential path traversal attempt detected',
          package: filePath,
          severity: 'CRITICAL',
          details: 'Code contains path traversal patterns'
        });
        break;
      }
    }
    
  } catch (error: any) {
    threats.push({
      type: 'FS_CONTEXT_ANALYSIS_ERROR',
      message: 'Failed to analyze file system context',
      package: filePath,
      severity: 'LOW',
      details: `FS context analysis failed: ${error.message}`
    });
  }
  
  return threats;
}

/**
 * Analyze content entropy
 */
export function analyzeContentEntropy(content: string, contentType: string, packageName: string): Threat[] {
  const threats: Threat[] = [];
  
  try {
    // Calculate Shannon entropy
    const entropy = calculateShannonEntropy(content);
    
    // Different thresholds for different content types
    let threshold: number;
    switch (contentType) {
      case 'javascript':
        threshold = 4.5;
        break;
      case 'json':
        threshold = 3.5;
        break;
      case 'text':
        threshold = 4.0;
        break;
      default:
        threshold = 4.0;
    }
    
    if (entropy > threshold) {
      threats.push({
        type: 'HIGH_ENTROPY_CONTENT',
        message: 'High entropy content detected',
        package: packageName,
        severity: 'MEDIUM',
        details: `Content has high entropy (${entropy.toFixed(2)}), possibly obfuscated`
      });
    }
    
  } catch (error: any) {
    threats.push({
      type: 'ENTROPY_ANALYSIS_ERROR',
      message: 'Failed to analyze content entropy',
      package: packageName,
      severity: 'LOW',
      details: `Entropy analysis failed: ${error.message}`
    });
  }
  
  return threats;
}

/**
 * Helper function to calculate Shannon entropy
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

/**
 * Helper function to download file
 */
function downloadFile(url: string, filePath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(filePath);
    const request = https.get(url, (response) => {
      response.pipe(file);
      
      file.on('finish', () => {
        file.close();
        resolve();
      });
      
      file.on('error', (err) => {
        fs.unlink(filePath, () => {}); // Delete the file on error
        reject(err);
      });
    });
    
    request.on('error', (err) => {
      request.destroy();
      reject(err);
    });
    
    request.on('timeout', () => {
      request.destroy();
      reject(new Error('Request timeout'));
    });
    
    // Set timeout and ensure cleanup
    request.setTimeout(30000);
    
    // Force cleanup after timeout
    const cleanupTimer = setTimeout(() => {
      if (!request.destroyed) {
        request.destroy();
      }
    }, 35000);
    cleanupTimer.unref(); // Don't keep process alive
    
    // Ensure request is properly destroyed on completion
    request.on('close', () => {
      clearTimeout(cleanupTimer);
    });
  });
}

/**
 * Helper function to analyze extracted files
 */
async function analyzeExtractedFiles(dirPath: string): Promise<Threat[]> {
  const threats: Threat[] = [];
  
  try {
    const files = fs.readdirSync(dirPath, { recursive: true });
    
    for (const file of files) {
      const filePath = path.join(dirPath, file as string);
      const stats = fs.statSync(filePath);
      
      if (stats.isFile()) {
        const content = fs.readFileSync(filePath, 'utf8');
        const fileName = path.basename(filePath);
        
        // Basic threat analysis for each file
        if (content.includes('eval(') || content.includes('Function(')) {
          threats.push({
            type: 'DYNAMIC_CODE_EXECUTION',
            message: 'Dynamic code execution detected in extracted file',
            package: fileName,
            severity: 'HIGH',
            details: `File "${fileName}" contains dynamic code execution`
          });
        }
        
        if (content.includes('require(') && content.includes('fs')) {
          threats.push({
            type: 'SUSPICIOUS_MODULE',
            message: 'Suspicious module usage in extracted file',
            package: fileName,
            severity: 'MEDIUM',
            details: `File "${fileName}" requires fs module`
          });
        }
      }
    }
  } catch (error: any) {
    threats.push({
      type: 'EXTRACTED_FILES_ANALYSIS_ERROR',
      message: 'Failed to analyze extracted files',
      package: 'unknown',
      severity: 'LOW',
      details: `Extracted files analysis failed: ${error.message}`
    });
  }
  
  return threats;
}
