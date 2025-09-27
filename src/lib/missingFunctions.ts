import { Threat, ThreatType } from '../types/core';
import * as fs from 'fs';
import * as path from 'path';
import * as https from 'https';
import * as http from 'http';
import { execSync } from 'child_process';

// Performance metrics tracking
const performanceMetrics = {
  startTime: null as number | null,
  packagesScanned: 0,
  cacheHits: 0,
  cacheMisses: 0,
  networkRequests: 0,
  errors: 0
};

// Cache for package metadata and results
const packageCache = new Map<string, any>();

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
  const result = packageCache.get(key);
  if (result) {
    performanceMetrics.cacheHits++;
    return result;
  }
  performanceMetrics.cacheMisses++;
  return null;
}

/**
 * Set cached result
 */
export function setCachedResult(key: string, data: Threat[]): void {
  packageCache.set(key, data);
}

/**
 * Get package metadata from npm registry
 */
export async function getPackageMetadata(packageName: string, version: string = 'latest'): Promise<any> {
  const cacheKey = `metadata:${packageName}@${version}`;
  const cached = packageCache.get(cacheKey);
  if (cached) {
    return cached;
  }

  performanceMetrics.networkRequests++;
  
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
            packageCache.set(cacheKey, versionData);
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
      performanceMetrics.errors++;
      reject(error);
    });

    request.on('close', () => {
      // Clean up
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

  performanceMetrics.networkRequests++;

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
      performanceMetrics.errors++;
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
 * Download tarball from URL
 */
export async function downloadTarball(tarballUrl: string): Promise<Buffer> {
  performanceMetrics.networkRequests++;
  
  return new Promise((resolve, reject) => {
    const protocol = tarballUrl.startsWith('https:') ? https : http;
    
    const request = protocol.get(tarballUrl, (response) => {
      const chunks: Buffer[] = [];
      
      response.on('data', (chunk: Buffer) => {
        chunks.push(chunk);
      });
      
      response.on('end', () => {
        resolve(Buffer.concat(chunks));
      });
      
      response.on('error', (error: any) => {
        performanceMetrics.errors++;
        reject(error);
      });
    });
    
    request.on('error', (error: any) => {
      performanceMetrics.errors++;
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
        performanceMetrics.errors++;
        reject(error);
      });
      
      stream.on('end', () => {
        resolve();
      });
      
      // Pipe the buffer through gunzip and then tar
      const gunzip = zlib.createGunzip();
      gunzip.on('error', (error: any) => {
        performanceMetrics.errors++;
        reject(error);
      });
      
      gunzip.pipe(stream);
      gunzip.write(tarballBuffer);
      gunzip.end();
      
    } catch (error) {
      performanceMetrics.errors++;
      reject(error);
    }
  });
}

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
      } catch (error) {
        // Ignore permission errors
      }
    }
    
    scanDir(dirPath);
  } catch (error) {
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
          'malware', 'virus', 'trojan', 'backdoor', 'keylogger', 'stealer',
          'ransomware', 'spyware', 'adware', 'rootkit', 'botnet', 'exploit',
          'payload', 'inject', 'hack', 'crack', 'keygen', 'cracked', 'pirated', 'stolen'
        ];
        
        for (const pattern of suspiciousPatterns) {
          if (fileName.includes(pattern)) {
            suspiciousFiles.push(itemPath);
            break;
          }
        }
        
        // Check for suspicious extensions
        const suspiciousExtensions = [
          '.exe', '.bat', '.cmd', '.scr', '.pif', '.com', '.dll', '.sys',
          '.vbs', '.ps1', '.sh'
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
            'malware', 'virus', 'trojan', 'backdoor', 'keylogger', 'stealer',
            'hack', 'crack', 'exploit'
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

/**
 * Get performance metrics
 */
export function getPerformanceMetrics() {
  return { ...performanceMetrics };
}

/**
 * Reset performance metrics
 */
export function resetPerformanceMetrics() {
  performanceMetrics.startTime = null;
  performanceMetrics.packagesScanned = 0;
  performanceMetrics.cacheHits = 0;
  performanceMetrics.cacheMisses = 0;
  performanceMetrics.networkRequests = 0;
  performanceMetrics.errors = 0;
}

/**
 * Update performance metrics
 */
export function updatePerformanceMetrics(updates: Partial<typeof performanceMetrics>) {
  Object.assign(performanceMetrics, updates);
}
