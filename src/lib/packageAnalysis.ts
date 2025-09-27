import { Threat, ThreatType } from '../types/core';
import { ScanOptions } from '../types/core';
import * as https from 'https';
import { execSync } from 'child_process';
import {
  checkWalletHijacking,
  checkNetworkManipulation,
  checkMultiChainTargeting,
  checkStealthControls,
  checkObfuscatedIoCs,
  detectDynamicRequires
} from './threatDetection';

import {
  checkGpgSignatures,
  checkPackageSignatures,
  checkPackageIntegrity,
  checkTarballSignatures,
  checkPackageJsonSignatures,
  checkMaintainerSignatures
} from './securityVerification';

import {
  analyzePackageJson,
  analyzeContentEntropy
} from './advancedAnalysis';

// Cache for package metadata and results
const cache = new Map<string, any>();

/**
 * Get npm global prefix
 */
export function getNpmGlobalPrefix(): string {
  try {
    return execSync('npm config get prefix', { encoding: 'utf8' }).trim();
  } catch {
    return '/usr/local';
  }
}

/**
 * Get cached result
 */
export function getCachedResult(key: string): Threat[] | null {
  return cache.get(key) || null;
}

/**
 * Set cached result
 */
export function setCachedResult(key: string, data: Threat[]): void {
  cache.set(key, data);
}

/**
 * Get package metadata from npm registry
 */
export async function getPackageMetadata(packageName: string, version: string = 'latest'): Promise<any> {
  const cacheKey = `metadata:${packageName}@${version}`;
  const cached = cache.get(cacheKey);
  if (cached) {
    return cached;
  }

  return new Promise((resolve, reject) => {
    const url = `https://registry.npmjs.org/${encodeURIComponent(packageName)}`;
    const request = https.get(url, (response) => {
      let data = '';
      
      response.on('data', (chunk) => {
        data += chunk;
      });
      
      response.on('end', () => {
        try {
          const packageData = JSON.parse(data);
          const distTags = packageData['dist-tags'] as any;
          const versionData = packageData.versions?.[version] || distTags?.[version];
          
          if (versionData) {
            cache.set(cacheKey, versionData);
            resolve(versionData);
          } else {
            resolve(null);
          }
        } catch (error) {
          reject(error);
        }
      });
    });

    request.on('error', (error) => {
      reject(error);
    });

    request.on('close', () => {
      // Clean up any timers
    });

    // Set timeout
    const timeout = setTimeout(() => {
      request.destroy();
      reject(new Error('Request timeout'));
    }, 10000);

    request.on('close', () => {
      clearTimeout(timeout);
    });
  });
}

/**
 * Download package files
 */
export async function downloadPackageFiles(packageData: any): Promise<string> {
  if (!packageData.dist?.tarball) {
    return '';
  }

  return new Promise((resolve, reject) => {
    const request = https.get(packageData.dist.tarball, (response) => {
      let data = '';
      
      response.on('data', (chunk) => {
        data += chunk;
      });
      
      response.on('end', () => {
        resolve(data);
      });
    });

    request.on('error', (error) => {
      reject(error);
    });

    request.on('close', () => {
      // Clean up
    });

    // Set timeout
    const timeout = setTimeout(() => {
      request.destroy();
      reject(new Error('Download timeout'));
    }, 30000);

    request.on('close', () => {
      clearTimeout(timeout);
    });
  });
}

/**
 * Check postinstall scripts
 */
export async function checkPostinstallScripts(packageData: any): Promise<Threat[]> {
  const threats: Threat[] = [];
  
  if (!packageData) {
    return threats;
  }

  const scripts = packageData.scripts || {};
  
  // Check for suspicious postinstall scripts
  if (scripts.postinstall) {
    const script = scripts.postinstall.toLowerCase();
    
    // Check for suspicious patterns
    const suspiciousPatterns = [
      'eval(',
      'function(',
      'require(',
      'child_process',
      'fs.',
      'http',
      'https',
      'net',
      'crypto'
    ];
    
    const hasSuspiciousPattern = suspiciousPatterns.some(pattern => 
      script.includes(pattern)
    );
    
    if (hasSuspiciousPattern) {
      threats.push({
        type: 'SUSPICIOUS_SCRIPT' as ThreatType,
        severity: 'HIGH',
        package: packageData.name || 'unknown',
        message: 'Suspicious postinstall script detected',
        details: `Postinstall script contains potentially malicious code: ${scripts.postinstall.substring(0, 100)}...`
      });
    }
  }
  
  return threats;
}

/**
 * Check code entropy
 */
export async function checkCodeEntropy(packageData: any): Promise<Threat[]> {
  const threats: Threat[] = [];
  
  if (!packageData) {
    return threats;
  }

  try {
    const content = JSON.stringify(packageData);
    const entropy = calculateEntropy(content);
    
    // High entropy indicates obfuscation
    if (entropy > 4.5) {
      threats.push({
        type: 'HIGH_ENTROPY_CONTENT' as ThreatType,
        severity: 'MEDIUM',
        package: packageData.name || 'unknown',
        message: 'High entropy content detected',
        details: `Package content has high entropy (${entropy.toFixed(2)}), indicating possible obfuscation`
      });
    }
  } catch (error) {
    // Ignore entropy calculation errors
  }
  
  return threats;
}

/**
 * Calculate entropy (simpler version)
 */
export function calculateEntropy(str: string): number {
  const freq: { [key: string]: number } = {};
  const len = str.length;
  
  // Count character frequencies
  for (let i = 0; i < len; i++) {
    const char = str[i];
    if (char) {
      freq[char] = (freq[char] || 0) + 1;
    }
  }
  
  // Calculate entropy
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  
  return entropy;
}

/**
 * Check suspicious file patterns
 */
export async function checkSuspiciousFilePatterns(packageData: any): Promise<Threat[]> {
  const threats: Threat[] = [];
  
  if (!packageData) {
    return threats;
  }

  const files = packageData.files || [];
  
  // Check for suspicious file patterns
  const suspiciousPatterns = [
    /\.exe$/i,
    /\.bat$/i,
    /\.cmd$/i,
    /\.scr$/i,
    /\.pif$/i,
    /\.com$/i,
    /\.dll$/i,
    /\.sys$/i
  ];
  
  for (const file of files) {
    for (const pattern of suspiciousPatterns) {
      if (pattern.test(file)) {
        threats.push({
          type: 'SUSPICIOUS_FILE' as ThreatType,
          severity: 'HIGH',
          package: packageData.name || 'unknown',
          message: 'Suspicious file pattern detected',
          details: `Suspicious executable file found: ${file}`
        });
        break;
      }
    }
  }
  
  return threats;
}

/**
 * Check malicious patterns
 */
export async function checkMaliciousPatterns(packageData: any): Promise<Threat[]> {
  const threats: Threat[] = [];
  
  if (!packageData) {
    return threats;
  }

  const content = JSON.stringify(packageData);
  
  // Check for known malicious patterns
  const maliciousPatterns = [
    'eval(',
    'Function(',
    'setTimeout(',
    'setInterval(',
    'require(',
    'import(',
    'child_process',
    'fs.',
    'http',
    'https',
    'net',
    'crypto',
    'os.',
    'process.'
  ];
  
  for (const pattern of maliciousPatterns) {
    if (content.includes(pattern)) {
      threats.push({
        type: 'MALICIOUS_PATTERN' as ThreatType,
        severity: 'MEDIUM',
        package: packageData.name || 'unknown',
        message: 'Malicious pattern detected',
        details: `Package contains potentially malicious pattern: ${pattern}`
      });
    }
  }
  
  return threats;
}

/**
 * Scan package with comprehensive analysis
 */
export async function scanPackage(
  packageName: string, 
  version: string = 'latest', 
  options: ScanOptions = {}, 
  packagePath: string | null = null
): Promise<Threat[]> {
  const threats: Threat[] = [];
  
  try {
    // Check cache first
    const cacheKey = `${packageName}@${version}`;
    const cachedThreats = getCachedResult(cacheKey);
    if (cachedThreats) {
      return cachedThreats;
    }
    
    // Get package metadata from npm registry
    const packageData = await getPackageMetadata(packageName, version);
    if (!packageData) {
      if (options.verbose) {
        console.warn(`Warning: Could not fetch metadata for ${packageName}`);
      }
      return threats;
    }
    
    // Heuristic 1: Check for postinstall scripts
    const postinstallThreats = await checkPostinstallScripts(packageData);
    threats.push(...postinstallThreats);
    
    // Heuristic 2: Entropy analysis for obfuscated code
    const entropyThreats = await checkCodeEntropy(packageData);
    threats.push(...entropyThreats);
    
    // Heuristic 3: Check for suspicious file patterns
    const filePatternThreats = await checkSuspiciousFilePatterns(packageData);
    threats.push(...filePatternThreats);
    
    // Heuristic 4: Check for known malicious patterns
    const patternThreats = await checkMaliciousPatterns(packageData);
    threats.push(...patternThreats);
    
    // Heuristic 5: Check for wallet hijacking attempts
    const walletThreats = await checkWalletHijacking(packageData);
    threats.push(...walletThreats);
    
    // Heuristic 6: Check for network response manipulation
    const networkThreats = await checkNetworkManipulation(packageData);
    threats.push(...networkThreats);
    
    // Heuristic 7: Check for multi-chain targeting
    const multiChainThreats = await checkMultiChainTargeting(packageData);
    threats.push(...multiChainThreats);
    
    // Heuristic 8: Check for stealth controls and obfuscation
    const stealthThreats = await checkStealthControls(packageData);
    threats.push(...stealthThreats);
    
    // Heuristic 9: Check for specific obfuscated IoCs
    const packageContent = JSON.stringify(packageData);
    const iocThreats = checkObfuscatedIoCs(packageContent, packageName);
    threats.push(...iocThreats);
    
    // Heuristic 10: Dynamic require() detection
    const dynamicRequireThreats = detectDynamicRequires(packageContent, packageName);
    threats.push(...dynamicRequireThreats);
    
    // Heuristic 11: Enhanced package.json static analysis
    const packageJsonThreats = analyzePackageJson(packageData, packageName);
    threats.push(...packageJsonThreats);
    
    // Heuristic 12: Enhanced entropy analysis
    const enhancedEntropyThreats = analyzeContentEntropy(packageContent, 'JSON', packageName);
    threats.push(...enhancedEntropyThreats);
    
    // Heuristic 13: Signature verification and tampering detection
    const signatureThreats = await checkPackageSignatures(packageData, packageName, options);
    threats.push(...signatureThreats);
    
    // Heuristic 14: Package integrity verification
    const integrityThreats = await checkPackageIntegrity(packageData, packageName);
    threats.push(...integrityThreats);
    
    // Heuristic 15: Tarball signature verification
    const tarballThreats = await checkTarballSignatures(packageData, packageName, options);
    threats.push(...tarballThreats);
    
    // Heuristic 16: Package.json signature verification
    const packageJsonSignatureThreats = await checkPackageJsonSignatures(packageData, packageName);
    threats.push(...packageJsonSignatureThreats);
    
    // Heuristic 17: Maintainer signature verification
    const maintainerThreats = await checkMaintainerSignatures(packageData, packageName);
    threats.push(...maintainerThreats);
    
    // Heuristic 18: GPG signature verification
    const gpgThreats = await checkGpgSignatures(packageData, packageName, options);
    threats.push(...gpgThreats);
    
    // Cache the results
    setCachedResult(cacheKey, threats);
    
  } catch (error: any) {
    if (options.verbose) {
      console.warn(`Warning: Could not scan ${packageName}: ${error.message}`);
    }
  }
  
  // Add package path to threats if provided
  if (packagePath) {
    threats.forEach(threat => {
      threat.package = packagePath;
    });
  }
  
  return threats;
}
