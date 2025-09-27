import * as fs from 'fs';
import * as path from 'path';
import { Threat, ThreatType } from '../types/core';

/**
 * Find JavaScript files in a directory using glob patterns
 */
export async function findJavaScriptFiles(dirPath: string): Promise<string[]> {
  const jsFiles: string[] = [];
  
  try {
    // Recursive function to scan directories
    function scanDir(currentPath: string) {
      try {
        const items = fs.readdirSync(currentPath);
        
        for (const item of items) {
          const itemPath = path.join(currentPath, item);
          const stats = fs.statSync(itemPath);
          
          if (stats.isDirectory() && !item.startsWith('.') && item !== 'node_modules') {
            scanDir(itemPath);
          } else if (stats.isFile()) {
            const ext = path.extname(item).toLowerCase();
            if (['.js', '.jsx', '.ts', '.tsx', '.mjs'].includes(ext)) {
              // Skip minified and bundle files
              if (!item.includes('.min.') && !item.includes('.bundle.')) {
                jsFiles.push(itemPath);
              }
            }
          }
        }
      } catch {
        // Ignore permission errors
      }
    }
    
    scanDir(dirPath);
  } catch {
    // Return empty array if directory doesn't exist
  }
  
  return jsFiles;
}

/**
 * Get suspicious files based on naming patterns
 */
export async function getSuspiciousFiles(dirPath: string): Promise<string[]> {
  const suspiciousFiles: string[] = [];
  
  try {
    const items = fs.readdirSync(dirPath);
    
    for (const item of items) {
      const itemPath = path.join(dirPath, item);
      const stat = fs.statSync(itemPath);
      
      if (stat.isFile()) {
        const fileName = item.toLowerCase();
        
        // Check for suspicious file names
        const suspiciousPatterns = [
          'malware',
          'virus',
          'trojan',
          'backdoor',
          'keylogger',
          'stealer',
          'ransomware',
          'spyware',
          'adware',
          'rootkit',
          'botnet',
          'exploit',
          'payload',
          'inject',
          'hack',
          'crack',
          'keygen',
          'cracked',
          'pirated',
          'stolen'
        ];
        
        for (const pattern of suspiciousPatterns) {
          if (fileName.includes(pattern)) {
            suspiciousFiles.push(itemPath);
            break;
          }
        }
        
        // Check for suspicious extensions
        const suspiciousExtensions = [
          '.exe',
          '.bat',
          '.cmd',
          '.scr',
          '.pif',
          '.com',
          '.dll',
          '.sys',
          '.vbs',
          '.ps1',
          '.sh'
        ];
        
        const ext = path.extname(fileName).toLowerCase();
        if (suspiciousExtensions.includes(ext)) {
          suspiciousFiles.push(itemPath);
        }
      } else if (stat.isDirectory() && !item.startsWith('.') && item !== 'node_modules') {
        // Recursively check subdirectories
        const subSuspiciousFiles = await getSuspiciousFiles(itemPath);
        suspiciousFiles.push(...subSuspiciousFiles);
      }
    }
  } catch (error) {
    // Return empty array if directory doesn't exist or permission denied
  }
  
  return suspiciousFiles;
}

/**
 * Download tarball from URL
 */
export async function downloadTarball(tarballUrl: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const https = require('https');
    const http = require('http');
    
    const protocol = tarballUrl.startsWith('https:') ? https : http;
    
    const request = protocol.get(tarballUrl, (response: any) => {
      const chunks: Buffer[] = [];
      
      response.on('data', (chunk: Buffer) => {
        chunks.push(chunk);
      });
      
      response.on('end', () => {
        resolve(Buffer.concat(chunks));
      });
      
      response.on('error', (error: any) => {
        reject(error);
      });
    });
    
    request.on('error', (error: any) => {
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
 * Extract tarball to temporary directory
 */
export async function extractTarball(tarballBuffer: Buffer, tempDir: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const tar = require('tar');
    const zlib = require('zlib');
    
    try {
      // Create temp directory if it doesn't exist
      if (!fs.existsSync(tempDir)) {
        fs.mkdirSync(tempDir, { recursive: true });
      }
      
      // Extract tarball
      const stream = tar.extract({
        cwd: tempDir,
        strict: false
      });
      
      stream.on('error', (error: any) => {
        reject(error);
      });
      
      stream.on('end', () => {
        resolve();
      });
      
      // Pipe the buffer through gunzip and then tar
      const gunzip = zlib.createGunzip();
      gunzip.on('error', (error: any) => {
        reject(error);
      });
      
      gunzip.pipe(stream);
      gunzip.write(tarballBuffer);
      gunzip.end();
      
    } catch (error) {
      reject(error);
    }
  });
}

/**
 * Analyze extracted files for threats
 */
export async function analyzeExtractedFiles(dirPath: string): Promise<Threat[]> {
  const threats: Threat[] = [];
  
  try {
    // Get all JavaScript files in the extracted directory
    const jsFiles = await findJavaScriptFiles(dirPath);
    
    for (const filePath of jsFiles) {
      try {
        const content = fs.readFileSync(filePath, 'utf8');
        
        // Check for suspicious patterns in each file
        const suspiciousPatterns = [
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
        
        for (const pattern of suspiciousPatterns) {
          if (content.includes(pattern)) {
            threats.push({
              type: 'SUSPICIOUS_FILE_CONTENT' as ThreatType,
              severity: 'MEDIUM',
              package: filePath,
              message: 'Suspicious file content detected',
              details: `File contains potentially suspicious pattern: ${pattern}`
            });
            break;
          }
        }
        
        // Check for high entropy content
        const entropy = calculateEntropy(content);
        if (entropy > 4.5) {
          threats.push({
            type: 'HIGH_ENTROPY_CONTENT' as ThreatType,
            severity: 'HIGH',
            package: filePath,
            message: 'High entropy content detected',
            details: `File has high entropy (${entropy.toFixed(2)}), indicating possible obfuscation`
          });
        }
        
      } catch (error) {
        // Skip files that can't be read
      }
    }
    
    // Check for suspicious files by name
    const suspiciousFiles = await getSuspiciousFiles(dirPath);
    for (const filePath of suspiciousFiles) {
      threats.push({
        type: 'SUSPICIOUS_FILE' as ThreatType,
        severity: 'HIGH',
        package: filePath,
        message: 'Suspicious file name detected',
        details: `File has suspicious name that may indicate malicious content`
      });
    }
    
  } catch (error) {
    threats.push({
      type: 'EXTRACTED_FILES_ANALYSIS_ERROR' as ThreatType,
      severity: 'LOW',
      package: dirPath,
      message: 'Error analyzing extracted files',
      details: `Could not analyze extracted files: ${error}`
    });
  }
  
  return threats;
}

/**
 * Calculate entropy of a string
 */
function calculateEntropy(str: string): number {
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
 * Scan node_modules directory
 */
export async function scanNodeModules(nodeModulesPath: string, _options: any): Promise<Threat[]> {
  const threats: Threat[] = [];
  
  try {
    if (!fs.existsSync(nodeModulesPath)) {
      return threats;
    }
    
    const packages = fs.readdirSync(nodeModulesPath);
    
    for (const packageName of packages) {
      const packagePath = path.join(nodeModulesPath, packageName);
      const packageJsonPath = path.join(packagePath, 'package.json');
      
      if (fs.existsSync(packageJsonPath)) {
        try {
          const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
          
          // Check for suspicious package names
          const suspiciousPatterns = [
            'malware',
            'virus',
            'trojan',
            'backdoor',
            'keylogger',
            'stealer',
            'hack',
            'crack',
            'exploit'
          ];
          
          for (const pattern of suspiciousPatterns) {
            if (packageName.toLowerCase().includes(pattern)) {
              threats.push({
                type: 'SUSPICIOUS_PACKAGE_NAME' as ThreatType,
                severity: 'HIGH',
                package: packageName,
                message: 'Suspicious package name detected',
                details: `Package name contains suspicious pattern: ${pattern}`
              });
              break;
            }
          }
          
          // Check for missing required fields
          if (!packageJson.name || !packageJson.version) {
            threats.push({
              type: 'MISSING_PACKAGE_FIELD' as ThreatType,
              severity: 'MEDIUM',
              package: packageName,
              message: 'Package missing required fields',
              details: `Package is missing required fields: name or version`
            });
          }
          
        } catch (error) {
          // Skip packages with invalid package.json
        }
      }
    }
    
  } catch (error) {
    threats.push({
      type: 'NODE_MODULES_SCAN_ERROR' as ThreatType,
      severity: 'LOW',
      package: nodeModulesPath,
      message: 'Error scanning node_modules',
      details: `Could not scan node_modules directory: ${error}`
    });
  }
  
  return threats;
}
