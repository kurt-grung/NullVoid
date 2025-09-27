/**
 * Main scan module for NullVoid
 * Migrated from scan.js to TypeScript
 */

import fs from 'fs';
import path from 'path';

// Import types
import { 
  ScanOptions, 
  ScanResult, 
  ProgressCallback, 
  Threat, 
  ThreatType,
  DirectoryStructure,
  PerformanceMetrics,
  ScanMetadata
} from './types';

// Import configuration
// import { CACHE_CONFIG } from './lib/config';

// Import utilities
import { isNullVoidCode, isTestFile } from './lib/nullvoidDetection';
import { InputValidator } from './lib/secureErrorHandler';
import {
  analyzeCodeStructure
} from './lib/detection';

import {
  scanPackage as scanPackageImpl
} from './lib/packageAnalysis';

import {
  buildAndScanDependencyTree,
  buildAndScanDependencyTreeParallel
} from './lib/dependencyTree';

import {
  findJavaScriptFiles,
  scanNodeModules
} from './lib/fileSystemUtils';

// Import missing functions
import {
  getPackageMetadata,
  downloadPackageFiles,
  getSuspiciousFiles,
  getPerformanceMetrics,
  resetPerformanceMetrics,
  updatePerformanceMetrics
} from './lib/missingFunctions';

import {
  analyzeCodeStructure as analyzeCodeStructureImpl,
  analyzeJavaScriptAST,
  analyzeFsUsageContext,
  analyzePackageTarball
} from './lib/analysisFunctions';

/**
 * Main scan function that performs heuristic checks on npm packages
 */
export async function scan(
  packageName?: string, 
  options: ScanOptions = {}, 
  progressCallback?: ProgressCallback
): Promise<ScanResult> {
  const startTime = Date.now();
  
  // Reset performance metrics
  resetPerformanceMetrics();
  updatePerformanceMetrics({ startTime });
  
  // Validate inputs
  try {
    if (packageName) {
      packageName = InputValidator.validatePackageName(packageName);
    }
    
    // Validate scan options
    const validatedOptions = InputValidator.validateScanOptions(options);
    options = { ...options, ...validatedOptions };
  } catch (error: any) {
    throw new Error(`Invalid scan parameters: ${error.message}`);
  }
  
  const threats: Threat[] = [];
  let filesScanned = 0;
  let packagesScanned = 0;
  let directoryStructure: DirectoryStructure | undefined;
  
  try {
    // If no package specified, scan current directory
    if (!packageName) {
      const directoryResult = await scanDirectory(process.cwd(), options, progressCallback);
      threats.push(...directoryResult.threats);
      filesScanned = directoryResult.filesScanned;
      packagesScanned = directoryResult.packagesScanned || 0;
      directoryStructure = directoryResult.directoryStructure;
      
      // Also scan any package.json files found in the directory
      const packageJsonPath = path.join(process.cwd(), 'package.json');
      if (fs.existsSync(packageJsonPath)) {
        try {
          const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
          const dependencies = {
            ...packageJson.dependencies,
            ...packageJson.devDependencies
          };
          
          if (Object.keys(dependencies).length > 0) {
            const maxDepth = options.maxDepth || 3;
            
            // Use parallel processing if enabled and multiple dependencies
            const useParallel = options.parallel !== false && Object.keys(dependencies).length > 1;
            
            let treeResult;
            if (useParallel) {
              try {
                treeResult = await buildAndScanDependencyTreeParallel(dependencies, maxDepth, options, 'root');
              } catch (error) {
                if (options.verbose) {
                  console.warn(`Warning: Parallel processing failed, falling back to sequential: ${error}`);
                }
                treeResult = await buildAndScanDependencyTree(dependencies, maxDepth, options);
              }
            } else {
              treeResult = await buildAndScanDependencyTree(dependencies, maxDepth, options);
            }
            
            threats.push(...treeResult.threats);
            packagesScanned += treeResult.packagesScanned;
          }
        } catch (error) {
          if (options.verbose) {
            console.warn(`Warning: Could not parse package.json: ${error}`);
          }
        }
      }
      
      // Scan node_modules if it exists
      const nodeModulesPath = path.join(process.cwd(), 'node_modules');
      if (fs.existsSync(nodeModulesPath)) {
        const nodeModulesThreats = await scanNodeModules(nodeModulesPath, options);
        threats.push(...nodeModulesThreats);
      }
      
      // Get suspicious files
      const suspiciousFiles = await getSuspiciousFiles(process.cwd());
      for (const file of suspiciousFiles) {
        threats.push({
          type: 'SUSPICIOUS_FILE' as ThreatType,
          severity: 'HIGH',
          package: file,
          message: 'Suspicious file detected',
          details: `File name or content suggests malicious intent: ${path.basename(file)}`
        });
      }
      
    } else if (fs.existsSync(packageName) && fs.statSync(packageName).isDirectory()) {
      // Scan directory
      const directoryResult = await scanDirectory(packageName, options, progressCallback);
      threats.push(...directoryResult.threats);
      filesScanned = directoryResult.filesScanned;
      packagesScanned = directoryResult.packagesScanned || 0;
      directoryStructure = directoryResult.directoryStructure;
      
      // Scan node_modules if it exists
      const nodeModulesPath = path.join(packageName, 'node_modules');
      if (fs.existsSync(nodeModulesPath)) {
        const nodeModulesThreats = await scanNodeModules(nodeModulesPath, options);
        threats.push(...nodeModulesThreats);
      }
      
      // Get suspicious files
      const suspiciousFiles = await getSuspiciousFiles(packageName);
      for (const file of suspiciousFiles) {
        threats.push({
          type: 'SUSPICIOUS_FILE' as ThreatType,
          severity: 'HIGH',
          package: file,
          message: 'Suspicious file detected',
          details: `File name or content suggests malicious intent: ${path.basename(file)}`
        });
      }
      
    } else if (fs.existsSync(packageName) && fs.statSync(packageName).isFile()) {
      // Scan individual file
      const fileThreats = await scanFile(packageName, options);
      threats.push(...fileThreats);
      filesScanned = 1;
      
      // Additional analysis for the file
      try {
        const content = fs.readFileSync(packageName, 'utf8');
        
        // Only analyze if not NullVoid's own code
        if (!isNullVoidCode(packageName) && !isTestFile(packageName)) {
          const codeStructureThreats = analyzeCodeStructureImpl(content, packageName);
          threats.push(...codeStructureThreats);
          
          const astThreats = analyzeJavaScriptAST(content, packageName);
          threats.push(...astThreats);
          
          const fsThreats = analyzeFsUsageContext(content, packageName);
          threats.push(...fsThreats);
        }
      } catch (error) {
        // Skip binary files
      }
      
    } else {
      // Try to scan as npm package
      const packageThreats = await scanPackage(packageName, 'latest', options);
      threats.push(...packageThreats);
      packagesScanned = 1;
      
      // Get package metadata for additional analysis
      try {
        const packageData = await getPackageMetadata(packageName, 'latest');
        if (packageData) {
          // Analyze package tarball
          const tarballThreats = await analyzePackageTarball(packageData);
          threats.push(...tarballThreats);
          
          // Download and analyze package files
          const packageFiles = await downloadPackageFiles(packageData);
          if (packageFiles) {
            const contentThreats = analyzeCodeStructureImpl(packageFiles, packageName);
            threats.push(...contentThreats);
          }
        }
      } catch (error) {
        if (options.verbose) {
          console.warn(`Warning: Could not analyze package metadata for ${packageName}: ${error}`);
        }
      }
      
      // Also check if it's a local package with dependencies
      const packageJsonPath = path.join(packageName, 'package.json');
      if (fs.existsSync(packageJsonPath)) {
        try {
          const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
          const dependencies = {
            ...packageJson.dependencies,
            ...packageJson.devDependencies
          };
          
          if (Object.keys(dependencies).length > 0) {
            const maxDepth = options.maxDepth || 3;
            
            // Use parallel processing if enabled and multiple dependencies
            const useParallel = options.parallel !== false && Object.keys(dependencies).length > 1;
            
            let treeResult;
            if (useParallel) {
              try {
                treeResult = await buildAndScanDependencyTreeParallel(dependencies, maxDepth, options, 'root');
              } catch (error) {
                if (options.verbose) {
                  console.warn(`Warning: Parallel processing failed, falling back to sequential: ${error}`);
                }
                treeResult = await buildAndScanDependencyTree(dependencies, maxDepth, options);
              }
            } else {
              treeResult = await buildAndScanDependencyTree(dependencies, maxDepth, options);
            }
            
            threats.push(...treeResult.threats);
            packagesScanned += treeResult.packagesScanned;
          }
        } catch (error) {
          if (options.verbose) {
            console.warn(`Warning: Could not parse package.json: ${error}`);
          }
        }
      }
    }
    
    // Deduplicate threats to match original JavaScript behavior
    const uniqueThreats = deduplicateThreats(threats);
    
    // Calculate performance metrics
    const endTime = Date.now();
    const performanceMetricsData = getPerformanceMetrics();
    const performance: PerformanceMetrics = {
      scanTime: endTime - startTime,
      staticAnalysisTime: endTime - startTime,
      sandboxAnalysisTime: 0,
      memoryUsage: process.memoryUsage().heapUsed,
      cpuUsage: 0,
      packagesScanned: performanceMetricsData.packagesScanned,
      cacheHits: performanceMetricsData.cacheHits,
      cacheMisses: performanceMetricsData.cacheMisses,
      cacheHitRate: performanceMetricsData.cacheHits / (performanceMetricsData.cacheHits + performanceMetricsData.cacheMisses) || 0,
      networkRequests: performanceMetricsData.networkRequests,
      errors: performanceMetricsData.errors,
      packagesPerSecond: performanceMetricsData.packagesScanned / ((endTime - startTime) / 1000) || 0,
      duration: endTime - startTime
    };
    
    // Create scan metadata
    const metadata: ScanMetadata = {
      startTime: new Date(startTime),
      endTime: new Date(endTime),
      version: '1.3.18',
      nodeVersion: process.version,
      platform: process.platform,
      target: packageName || process.cwd()
    };
    
    return {
      threats: uniqueThreats,
      filesScanned,
      packagesScanned,
      directoryStructure: directoryStructure || {
        directories: [],
        files: [],
        totalDirectories: 0,
        totalFiles: 0
      },
      performance,
      metadata
    };
    
  } catch (error: any) {
    throw new Error(`Scan failed: ${error.message}`);
  }
}

/**
 * Scan a directory for JavaScript files and suspicious patterns
 */
async function scanDirectory(
  dirPath: string, 
  options: ScanOptions, 
  progressCallback?: ProgressCallback
): Promise<{ threats: Threat[], filesScanned: number, packagesScanned?: number, directoryStructure: DirectoryStructure }> {
  const threats: Threat[] = [];
  let filesScanned = 0;
  
  const directoryStructure: DirectoryStructure = {
    directories: [],
    files: [],
    totalDirectories: 0,
    totalFiles: 0
  };
  
  try {
    // Get all JavaScript files in the directory
    const jsFiles = await getJavaScriptFiles(dirPath);
    
    // Remove duplicates to prevent processing the same file twice
    const uniqueFiles = [...new Set(jsFiles)];
    
    // Track processed files to prevent duplicates
    const processedFiles = new Set<string>();
    
    for (const filePath of uniqueFiles) {
      // Skip if already processed
      if (processedFiles.has(filePath)) {
        continue;
      }
      processedFiles.add(filePath);
      
      try {
        filesScanned++;
        
        // Update progress callback if provided
        if (progressCallback) {
          progressCallback(filePath);
        }
        
        // Use the sophisticated scanFile function for each file
        const fileThreats = await scanFile(filePath, options);
        threats.push(...fileThreats);
        
        // Additional analysis for each file
        try {
          const content = fs.readFileSync(filePath, 'utf8');
          
          // Only analyze if not NullVoid's own code
          if (!isNullVoidCode(filePath) && !isTestFile(filePath)) {
            // Code structure analysis
            const codeStructureThreats = analyzeCodeStructureImpl(content, filePath);
            threats.push(...codeStructureThreats);
            
            // AST analysis
            const astThreats = analyzeJavaScriptAST(content, filePath);
            threats.push(...astThreats);
            
            // File system usage analysis
            const fsThreats = analyzeFsUsageContext(content, filePath);
            threats.push(...fsThreats);
          }
          
        } catch (error) {
          // Skip binary files
        }
        
        // Add to directory structure
        directoryStructure.files.push(path.basename(filePath));
        directoryStructure.totalFiles++;
        
      } catch (error: any) {
        console.warn(`Warning: Could not analyze ${filePath}: ${error.message}`);
      }
    }
    
    // Scan subdirectories
    const items = fs.readdirSync(dirPath);
    for (const item of items) {
      const itemPath = path.join(dirPath, item);
      const stats = fs.statSync(itemPath);
      
      if (stats.isDirectory() && !item.startsWith('.') && item !== 'node_modules') {
        directoryStructure.directories.push(item);
        directoryStructure.totalDirectories++;
        
        // Recursively scan subdirectory
        const subResult = await scanDirectory(itemPath, options, progressCallback);
        threats.push(...subResult.threats);
        filesScanned += subResult.filesScanned;
        
        // Scan node_modules in subdirectory if it exists
        const nodeModulesPath = path.join(itemPath, 'node_modules');
        if (fs.existsSync(nodeModulesPath)) {
          const nodeModulesThreats = await scanNodeModules(nodeModulesPath, options);
          threats.push(...nodeModulesThreats);
        }
        
        // Get suspicious files in subdirectory
        const suspiciousFiles = await getSuspiciousFiles(itemPath);
        for (const file of suspiciousFiles) {
          threats.push({
            type: 'SUSPICIOUS_FILE' as ThreatType,
            severity: 'HIGH',
            package: file,
            message: 'Suspicious file detected',
            details: `File name or content suggests malicious intent: ${path.basename(file)}`
          });
        }
      }
    }
    
  } catch (error: any) {
    console.warn(`Warning: Could not scan directory ${dirPath}: ${error.message}`);
  }
  
  // Also scan any package.json files found in the directory for dependencies
  const packageJsonPath = path.join(dirPath, 'package.json');
  if (fs.existsSync(packageJsonPath)) {
    try {
      const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
      const dependencies = {
        ...packageJson.dependencies,
        ...packageJson.devDependencies
      };
      
      if (Object.keys(dependencies).length > 0) {
        const maxDepth = options.maxDepth || 3;
        
        // Use parallel processing if enabled and multiple dependencies
        const useParallel = options.parallel !== false && Object.keys(dependencies).length > 1;
        
        let treeResult;
        if (useParallel) {
          try {
            treeResult = await buildAndScanDependencyTreeParallel(dependencies, maxDepth, options, 'root');
          } catch (error) {
            if (options.verbose) {
              console.warn(`Warning: Parallel processing failed, falling back to sequential: ${error}`);
            }
            treeResult = await buildAndScanDependencyTree(dependencies, maxDepth, options);
          }
        } else {
          treeResult = await buildAndScanDependencyTree(dependencies, maxDepth, options);
        }
        
        threats.push(...treeResult.threats);
        // Update packagesScanned in the return value
        return {
          threats,
          filesScanned,
          packagesScanned: treeResult.packagesScanned,
          directoryStructure
        };
      }
    } catch (error) {
      if (options.verbose) {
        console.warn(`Warning: Could not parse package.json: ${error}`);
      }
    }
  }
  
  // Check for suspicious files in the directory
  const suspiciousFiles = await getSuspiciousFiles(dirPath);
  for (const file of suspiciousFiles) {
    threats.push({
      type: 'SUSPICIOUS_FILE' as ThreatType,
      severity: 'HIGH',
      package: file,
      message: 'Suspicious file detected',
      details: `File name or content suggests malicious intent: ${path.basename(file)}`
    });
  }
  
  // Also scan node_modules if it exists
  const nodeModulesPath = path.join(dirPath, 'node_modules');
  if (fs.existsSync(nodeModulesPath)) {
    try {
      const nodeModulesThreats = await scanNodeModules(nodeModulesPath, options);
      threats.push(...nodeModulesThreats);
    } catch (error) {
      if (options.verbose) {
        console.warn(`Warning: Could not scan node_modules: ${error}`);
      }
    }
  }
  
  return {
    threats,
    filesScanned,
    packagesScanned: 0,
    directoryStructure
  };
}

/**
 * Scan a single file for threats
 */
async function scanFile(filePath: string, _options: ScanOptions): Promise<Threat[]> {
  const threats: Threat[] = [];
  
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const fileName = path.basename(filePath);
    const absolutePath = path.resolve(filePath); // Use absolute path
    
    // Check if it's a JavaScript file
    if (fileName.endsWith('.js') || fileName.endsWith('.mjs') || fileName.endsWith('.ts')) {
      try {
        // Note: Original JavaScript version doesn't call detectWalletHijacking for directory scans
        // Commenting out to match original behavior exactly
        // const walletThreats = detectWalletHijacking(content, fileName);
        // threats.push(...walletThreats.map(threat => ({
        //   ...threat,
        //   type: threat.type as any,
        //   severity: threat.severity as any,
        //   package: absolutePath
        // })));
        
        // Critical: Add malicious code structure analysis
        const codeAnalysis = analyzeCodeStructure(content);
        if (codeAnalysis.isMalicious && !isNullVoidCode(absolutePath) && !isTestFile(absolutePath)) {
          const threat: any = {
            type: 'MALICIOUS_CODE_STRUCTURE',
            message: 'Code structure indicates malicious obfuscated content',
            package: absolutePath, // Use absolute path
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
        
        // Note: Original JavaScript version doesn't call detectObfuscatedIoCs for directory scans
        // Commenting out to match original behavior exactly
        // const iocThreats = detectObfuscatedIoCs(content, absolutePath);
        // threats.push(...iocThreats.map(threat => ({
        //   ...threat,
        //   type: threat.type as any,
        //   severity: threat.severity as any,
        //   package: absolutePath
        // })));
        
        // Note: Original JavaScript version doesn't call detectDynamicRequires for directory scans
        // Commenting out to match original behavior exactly
        // const requireThreats = detectDynamicRequires(content, absolutePath);
        // threats.push(...requireThreats.map(threat => ({
        //   ...threat,
        //   type: threat.type as any,
        //   severity: threat.severity as any,
        //   package: absolutePath
        // })));
        
        // Note: Original JavaScript version doesn't call analyzeJavaScriptAST for directory scans
        // Commenting out to match original behavior exactly
        // const astThreats = analyzeJavaScriptAST(content, absolutePath);
        // const filteredAstThreats = astThreats.filter(threat => threat.type !== 'MALICIOUS_CODE_STRUCTURE');
        // threats.push(...filteredAstThreats.map(threat => ({
        //   ...threat,
        //   type: threat.type as any,
        //   severity: threat.severity as any,
        //   package: absolutePath
        // })));
        
        // Basic threat detection as fallback
        if (content.includes('eval(') && !isNullVoidCode(absolutePath) && !isTestFile(absolutePath)) {
          threats.push({
            type: 'MALICIOUS_CODE_STRUCTURE',
            message: 'Code contains eval() function',
            package: absolutePath, // Use absolute path
            severity: 'HIGH',
            details: 'Code contains eval() which can be used for code injection',
            confidence: 0.8
          });
        }
        
        if (content.includes('require(') && content.includes('fs') && !isNullVoidCode(absolutePath) && !isTestFile(absolutePath)) {
          threats.push({
            type: 'SUSPICIOUS_MODULE',
            message: 'Code requires fs module',
            package: absolutePath, // Use absolute path
            severity: 'CRITICAL',
            details: 'Code requires fs module which can be used for file system access',
            confidence: 0.9
          });
        }
        
      } catch (error: any) {
        console.warn(`Warning: Could not analyze file ${filePath}: ${error.message}`);
      }
    } else {
      // Non-JavaScript file - check for suspicious patterns safely
      try {
        // Check for obfuscated patterns even in non-JS files (placeholder)
        // const iocThreats = checkObfuscatedIoCs(content, fileName);
        // threats.push(...iocThreats);
      } catch (error: any) {
        console.warn(`Warning: Could not analyze file ${filePath}: ${error.message}`);
      }
    }
    
  } catch (error: any) {
    console.warn(`Warning: Could not analyze file ${filePath}: ${error.message}`);
  }
  
  return threats;
}

/**
 * Scan an npm package
 */
async function scanPackage(packageName: string, version: string, options: ScanOptions): Promise<Threat[]> {
  return await scanPackageImpl(packageName, version, options);
}

/**
 * Get all JavaScript files in a directory recursively
 */
async function getJavaScriptFiles(dirPath: string): Promise<string[]> {
  return await findJavaScriptFiles(dirPath);
}

/**
 * Deduplicate threats to match original JavaScript behavior
 * Keeps only unique threats based on type, package, and details
 */
function deduplicateThreats(threats: Threat[]): Threat[] {
  const seen = new Set<string>();
  const uniqueThreats: Threat[] = [];
  
  for (const threat of threats) {
    // Create a unique key based on type, package, and key details
    const key = `${threat.type}:${threat.package}:${threat.message}`;
    
    if (!seen.has(key)) {
      seen.add(key);
      uniqueThreats.push(threat);
    }
  }
  
  return uniqueThreats;
}