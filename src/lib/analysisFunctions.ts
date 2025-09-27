import { Threat, ThreatType } from '../types/core';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Analyze code structure for malicious patterns
 */
export function analyzeCodeStructure(code: string, packageName: string): Threat[] {
  const threats: Threat[] = [];
  
  // Check for suspicious code patterns
  const suspiciousPatterns = [
    /eval\s*\(/g,
    /Function\s*\(/g,
    /setTimeout\s*\(/g,
    /setInterval\s*\(/g,
    /require\s*\(/g,
    /import\s*\(/g,
    /process\.env/g,
    /fs\./g,
    /child_process/g,
    /exec\s*\(/g,
    /spawn\s*\(/g
  ];
  
  for (const pattern of suspiciousPatterns) {
    const matches = code.match(pattern);
    if (matches && matches.length > 5) {
      threats.push({
        type: 'SUSPICIOUS_CODE_STRUCTURE' as ThreatType,
        severity: 'HIGH',
        package: packageName,
        message: 'Suspicious code patterns detected',
        details: `Found ${matches.length} instances of potentially dangerous code patterns`
      });
      break;
    }
  }
  
  // Check for obfuscated code
  const obfuscatedPatterns = [
    /[a-zA-Z]{1,2}\s*=\s*[a-zA-Z]{1,2}/g,
    /String\.fromCharCode/g,
    /atob\s*\(/g,
    /btoa\s*\(/g,
    /decodeURIComponent/g,
    /encodeURIComponent/g
  ];
  
  for (const pattern of obfuscatedPatterns) {
    const matches = code.match(pattern);
    if (matches && matches.length > 3) {
      threats.push({
        type: 'OBFUSCATED_CODE' as ThreatType,
        severity: 'MEDIUM',
        package: packageName,
        message: 'Obfuscated code detected',
        details: `Found ${matches.length} instances of code obfuscation patterns`
      });
      break;
    }
  }
  
  return threats;
}

/**
 * Analyze JavaScript AST for malicious patterns
 */
export function analyzeJavaScriptAST(code: string, packageName: string): Threat[] {
  const threats: Threat[] = [];
  
  try {
    // Simple AST analysis without external dependencies
    const astPatterns = [
      // Check for suspicious function calls
      /eval\s*\(/g,
      /Function\s*\(/g,
      /setTimeout\s*\(/g,
      /setInterval\s*\(/g,
      /require\s*\(/g,
      /import\s*\(/g,
      
      // Check for suspicious object access
      /process\.env/g,
      /process\.argv/g,
      /process\.cwd/g,
      /process\.exit/g,
      
      // Check for file system access
      /fs\./g,
      /readFile/g,
      /writeFile/g,
      /unlink/g,
      /mkdir/g,
      /rmdir/g,
      
      // Check for process spawning
      /child_process/g,
      /exec\s*\(/g,
      /spawn\s*\(/g,
      /fork\s*\(/g,
      
      // Check for network access
      /http\./g,
      /https\./g,
      /request\s*\(/g,
      /fetch\s*\(/g,
      
      // Check for crypto operations
      /crypto\./g,
      /createHash/g,
      /createHmac/g,
      /randomBytes/g
    ];
    
    for (const pattern of astPatterns) {
      const matches = code.match(pattern);
      if (matches && matches.length > 3) {
        threats.push({
          type: 'SUSPICIOUS_CODE_STRUCTURE' as ThreatType,
          severity: 'HIGH',
          package: packageName,
          message: 'Suspicious AST patterns detected',
          details: `Found ${matches.length} instances of potentially dangerous AST patterns`
        });
        break;
      }
    }
    
    // Check for dynamic code generation
    const dynamicPatterns = [
      /new\s+Function/g,
      /eval\s*\(/g,
      /setTimeout\s*\(/g,
      /setInterval\s*\(/g
    ];
    
    for (const pattern of dynamicPatterns) {
      const matches = code.match(pattern);
      if (matches && matches.length > 2) {
        threats.push({
          type: 'DYNAMIC_CODE_EXECUTION' as ThreatType,
          severity: 'HIGH',
          package: packageName,
          message: 'Dynamic code execution detected',
          details: `Found ${matches.length} instances of dynamic code execution`
        });
        break;
      }
    }
    
  } catch (error) {
    threats.push({
      type: 'ANALYSIS_ERROR' as ThreatType,
      severity: 'LOW',
      package: packageName,
      message: 'AST analysis failed',
      details: `Could not analyze AST: ${error}`
    });
  }
  
  return threats;
}

/**
 * Analyze file system usage context
 */
export function analyzeFsUsageContext(code: string, filePath: string): Threat[] {
  const threats: Threat[] = [];
  
  // Check for suspicious file system operations
  const fsPatterns = [
    /fs\.readFile/g,
    /fs\.writeFile/g,
    /fs\.unlink/g,
    /fs\.mkdir/g,
    /fs\.rmdir/g,
    /fs\.chmod/g,
    /fs\.chown/g,
    /fs\.stat/g,
    /fs\.lstat/g,
    /fs\.readdir/g,
    /fs\.readlink/g,
    /fs\.symlink/g,
    /fs\.link/g,
    /fs\.unlink/g,
    /fs\.rename/g,
    /fs\.copyFile/g
  ];
  
  for (const pattern of fsPatterns) {
    const matches = code.match(pattern);
    if (matches && matches.length > 5) {
      threats.push({
        type: 'SUSPICIOUS_FS_OPERATION' as ThreatType,
        severity: 'HIGH',
        package: filePath,
        message: 'Suspicious file system operations detected',
        details: `Found ${matches.length} instances of file system operations`
      });
      break;
    }
  }
  
  // Check for path traversal attempts
  const traversalPatterns = [
    /\.\.\//g,
    /\.\.\\/g,
    /\.\.%2f/g,
    /\.\.%5c/g,
    /\.\.%252f/g,
    /\.\.%255c/g
  ];
  
  for (const pattern of traversalPatterns) {
    const matches = code.match(pattern);
    if (matches && matches.length > 3) {
      threats.push({
        type: 'PATH_TRAVERSAL' as ThreatType,
        severity: 'CRITICAL',
        package: filePath,
        message: 'Path traversal attempt detected',
        details: `Found ${matches.length} instances of path traversal patterns`
      });
      break;
    }
  }
  
  return threats;
}

/**
 * Analyze package tarball for threats
 */
export async function analyzePackageTarball(packageData: any): Promise<Threat[]> {
  const threats: Threat[] = [];
  
  try {
    if (!packageData.dist?.tarball) {
      return threats;
    }
    
    // Check tarball size
    if (packageData.dist.size > 50 * 1024 * 1024) { // 50MB
      threats.push({
        type: 'SUSPICIOUS_FILE' as ThreatType,
        severity: 'MEDIUM',
        package: packageData.name,
        message: 'Large package size',
        details: `Package size is ${Math.round(packageData.dist.size / 1024 / 1024)}MB, which is unusually large`
      });
    }
    
    // Check for missing integrity hash
    if (!packageData.dist.integrity) {
      threats.push({
        type: 'MISSING_INTEGRITY_HASH' as ThreatType,
        severity: 'HIGH',
        package: packageData.name,
        message: 'Missing integrity hash',
        details: 'Package tarball does not have an integrity hash'
      });
    }
    
    // Check for suspicious file extensions in tarball
    const suspiciousExtensions = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.com', '.dll', '.sys'];
    const tarballUrl = packageData.dist.tarball;
    
    for (const ext of suspiciousExtensions) {
      if (tarballUrl.includes(ext)) {
        threats.push({
          type: 'SUSPICIOUS_FILE' as ThreatType,
          severity: 'CRITICAL',
          package: packageData.name,
          message: 'Suspicious file extension in tarball',
          details: `Tarball contains suspicious file extension: ${ext}`
        });
        break;
      }
    }
    
  } catch (error) {
    threats.push({
      type: 'TARBALL_ANALYSIS_ERROR' as ThreatType,
      severity: 'LOW',
      package: packageData.name || 'unknown',
      message: 'Tarball analysis failed',
      details: `Could not analyze tarball: ${error}`
    });
  }
  
  return threats;
}

/**
 * Analyze extracted files for threats
 */
export async function analyzeExtractedFiles(dirPath: string): Promise<Threat[]> {
  const threats: Threat[] = [];
  
  try {
    if (!fs.existsSync(dirPath)) {
      return threats;
    }
    
    const items = fs.readdirSync(dirPath);
    
    for (const item of items) {
      const itemPath = path.join(dirPath, item);
      const stat = fs.statSync(itemPath);
      
      if (stat.isFile()) {
        // Check for suspicious file names
        const suspiciousPatterns = [
          'malware', 'virus', 'trojan', 'backdoor', 'keylogger', 'stealer',
          'hack', 'crack', 'exploit', 'payload', 'inject'
        ];
        
        for (const pattern of suspiciousPatterns) {
          if (item.toLowerCase().includes(pattern)) {
            threats.push({
              type: 'SUSPICIOUS_FILE' as ThreatType,
              severity: 'HIGH',
              package: itemPath,
              message: 'Suspicious file name detected',
              details: `File name contains suspicious pattern: ${pattern}`
            });
            break;
          }
        }
        
        // Check for suspicious file extensions
        const suspiciousExtensions = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.com', '.dll', '.sys'];
        const ext = path.extname(item).toLowerCase();
        
        if (suspiciousExtensions.includes(ext)) {
          threats.push({
            type: 'SUSPICIOUS_FILE' as ThreatType,
            severity: 'CRITICAL',
            package: itemPath,
            message: 'Suspicious file extension detected',
            details: `File has suspicious extension: ${ext}`
          });
        }
        
        // Check file content for suspicious patterns
        try {
          const content = fs.readFileSync(itemPath, 'utf8');
          const contentThreats = analyzeCodeStructure(content, itemPath);
          threats.push(...contentThreats);
        } catch {
          // Skip binary files
        }
        
      } else if (stat.isDirectory()) {
        // Recursively analyze subdirectories
        const subThreats = await analyzeExtractedFiles(itemPath);
        threats.push(...subThreats);
      }
    }
    
  } catch (error) {
    threats.push({
      type: 'EXTRACTED_FILES_ANALYSIS_ERROR' as ThreatType,
      severity: 'LOW',
      package: dirPath,
      message: 'Extracted files analysis failed',
      details: `Could not analyze extracted files: ${error}`
    });
  }
  
  return threats;
}
