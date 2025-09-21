const fs = require('fs');
const path = require('path');
const https = require('https');
const { execSync } = require('child_process');
const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const t = require('@babel/types');
const acorn = require('acorn');
const walk = require('acorn-walk');
const tar = require('tar');
const glob = require('glob');
const fse = require('fs-extra');
const os = require('os');

// Simple in-memory cache for package analysis
const packageCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// Enhanced entropy thresholds for different content types
const ENTROPY_THRESHOLDS = {
  JAVASCRIPT: 4.5,    // Higher threshold for JS (more random)
  JSON: 3.8,          // Lower threshold for JSON
  TEXT: 3.5,          // General text content
  BINARY: 7.0         // Binary/encoded content
};

// Suspicious package.json patterns
const SUSPICIOUS_PACKAGE_PATTERNS = {
  scripts: [
    'curl.*http',
    'wget.*http', 
    'rm -rf',
    'chmod.*777',
    'eval.*',
    'node.*-e',
    'bash.*-c'
  ],
  dependencies: [
    'http://.*',
    'git://.*',
    'file://.*'
  ],
  keywords: [
    'malware',
    'virus',
    'trojan',
    'backdoor'
  ]
};

/**
 * Cache management functions
 */
function getCachedResult(key) {
  const cached = packageCache.get(key);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.data;
  }
  return null;
}

function setCachedResult(key, data) {
  packageCache.set(key, {
    data,
    timestamp: Date.now()
  });
}

/**
 * Main scan function that performs heuristic checks on npm packages
 * @param {string} packageName - Optional package name to scan
 * @param {object} options - Scan options
 * @returns {Promise<object>} Scan results
 */
async function scan(packageName, options = {}) {
  const startTime = Date.now();
  const threats = [];
  let packagesScanned = 0;
  let filesScanned = 0;
  let directoryStructure = null;

  try {
    // If no package specified, scan current directory's package.json
    if (!packageName) {
      const packageJsonPath = path.join(process.cwd(), 'package.json');
      if (fs.existsSync(packageJsonPath)) {
        const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
        const dependencies = {
          ...packageJson.dependencies,
          ...packageJson.devDependencies
        };
        
        for (const [name, version] of Object.entries(dependencies)) {
          const packageThreats = await scanPackage(name, version, options);
          threats.push(...packageThreats);
          packagesScanned++;
        }
        
        // Also scan node_modules directory for additional threats
        // Note: Disabled due to false positives with legitimate packages
        // const nodeModulesPath = path.join(process.cwd(), 'node_modules');
        // const nodeModulesThreats = await scanNodeModules(nodeModulesPath, options);
        // threats.push(...nodeModulesThreats);
        
      } else {
        // Scan current directory for JavaScript files and suspicious patterns
        const directoryResult = await scanDirectory(process.cwd(), options);
        threats.push(...directoryResult.threats);
        filesScanned = directoryResult.filesScanned;
        packagesScanned = 0; // This is a directory scan, not a package scan
        directoryStructure = directoryResult.directoryStructure;
      }
    } else {
      // Scan specific package
      const packageThreats = await scanPackage(packageName, 'latest', options);
      threats.push(...packageThreats);
      packagesScanned = 1;
    }

    return {
      threats,
      packagesScanned,
      filesScanned,
      directoryStructure,
      duration: Date.now() - startTime,
      timestamp: new Date().toISOString()
    };
  } catch (error) {
    throw new Error(`Scan failed: ${error.message}`);
  }
}

/**
 * Scan a specific package for threats
 * @param {string} packageName - Package name
 * @param {string} version - Package version
 * @param {object} options - Scan options
 * @returns {Promise<Array>} Array of threats found
 */
async function scanPackage(packageName, version, options) {
  const threats = [];
  
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
    
    // Heuristic 9: Advanced AST analysis
    const astThreats = await analyzePackageTarball(packageData);
    threats.push(...astThreats);
    
    // Heuristic 10: Check for specific obfuscated IoCs
    const packageContent = JSON.stringify(packageData);
    const iocThreats = checkObfuscatedIoCs(packageContent, packageName);
    threats.push(...iocThreats);
    
    // Heuristic 11: Enhanced package.json static analysis
    const packageJsonThreats = analyzePackageJson(packageData, packageName);
    threats.push(...packageJsonThreats);
    
    // Heuristic 12: Dynamic require() detection
    // Analyze package content for dynamic require patterns
    const packageContentForRequire = JSON.stringify(packageData);
    const dynamicRequireThreats = detectDynamicRequires(packageContentForRequire, packageName);
    threats.push(...dynamicRequireThreats);
    
    // Heuristic 13: Enhanced entropy analysis
    const enhancedEntropyThreats = analyzeContentEntropy(packageContent, 'JSON', packageName);
    threats.push(...enhancedEntropyThreats);
    
    // Cache the results
    setCachedResult(cacheKey, threats);
    
  } catch (error) {
    if (options.verbose) {
      console.warn(`Warning: Could not scan ${packageName}: ${error.message}`);
    }
  }
  
  return threats;
}

/**
 * Get package metadata from npm registry
 * @param {string} packageName - Package name
 * @param {string} version - Package version
 * @returns {Promise<object>} Package metadata
 */
async function getPackageMetadata(packageName, version) {
  return new Promise((resolve, reject) => {
    const url = `https://registry.npmjs.org/${packageName}`;
    
    https.get(url, (res) => {
      let data = '';
      
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        try {
          const packageData = JSON.parse(data);
          const versionData = packageData.versions?.[version] || packageData['dist-tags']?.latest;
          resolve(versionData);
        } catch (error) {
          reject(error);
        }
      });
    }).on('error', (error) => {
      reject(error);
    });
  });
}

/**
 * Download and analyze package files
 * @param {object} packageData - Package metadata
 * @returns {Promise<string>} Package file content
 */
async function downloadPackageFiles(packageData) {
  // This is a simplified version - in production you'd download the actual tarball
  // For now, we'll analyze the package.json and any available files
  let content = '';
  
  if (packageData.packageJson) {
    content += JSON.stringify(packageData.packageJson, null, 2);
  }
  
  // Add any other file content that might be available
  if (packageData.files) {
    content += '\n' + Object.keys(packageData.files).join('\n');
  }
  
  return content;
}

/**
 * Check for postinstall scripts that could execute malicious code
 */
async function checkPostinstallScripts(packageData) {
  const threats = [];
  
  if (!packageData || !packageData.scripts) {
    return threats;
  }
  
  const suspiciousScripts = [
    'curl', 'wget', 'eval', 'require', 'child_process',
    'fs.writeFile', 'fs.unlink', 'process.exit', 'exec',
    'spawn', 'fork', 'download', 'fetch'
  ];
  
  // Check all scripts for suspicious commands
  for (const [scriptName, scriptContent] of Object.entries(packageData.scripts)) {
    if (scriptName === 'postinstall' || scriptName === 'preinstall') {
      const lowerScript = scriptContent.toLowerCase();
      
      for (const suspicious of suspiciousScripts) {
        if (lowerScript.includes(suspicious)) {
          threats.push({
            type: 'POSTINSTALL_SCRIPT',
            message: `Package contains ${scriptName} script with suspicious commands`,
            package: packageData.name || 'unknown',
            severity: 'HIGH',
            details: `Script contains '${suspicious}' which could download and execute malicious code`
          });
          break;
        }
      }
    }
  }
  
  return threats;
}

/**
 * Analyze code entropy to detect obfuscated or packed code
 */
async function checkCodeEntropy(packageData) {
  const threats = [];
  
  if (!packageData) {
    return threats;
  }
  
  // Calculate Shannon entropy for package content
  const content = await downloadPackageFiles(packageData);
  const entropy = calculateShannonEntropy(content);
  
  // High entropy indicates obfuscation (threshold: 7.5)
  if (entropy > 7.5) {
    threats.push({
      type: 'SUSPICIOUS_ENTROPY',
      message: 'Package contains files with suspiciously high entropy (possible obfuscation)',
      package: packageData.name || 'unknown',
      severity: 'HIGH',
      details: `Detected entropy level: ${entropy.toFixed(2)} (threshold: 7.5)`
    });
  }
  
  return threats;
}

/**
 * Calculate Shannon entropy for text content
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
  
  for (const freq of Object.values(frequencies)) {
    const probability = freq / length;
    entropy -= probability * Math.log2(probability);
  }
  
  return entropy;
}

/**
 * Advanced AST Analysis for JavaScript code
 * @param {string} code - JavaScript code to analyze
 * @param {string} packageName - Package name for context
 * @returns {Array} Array of threats found
 */
function analyzeJavaScriptAST(code, packageName) {
  const threats = [];
  
  try {
    // Parse JavaScript code into AST
    const ast = parser.parse(code, {
      sourceType: 'module',
      allowImportExportEverywhere: true,
      allowReturnOutsideFunction: true,
      plugins: ['jsx', 'typescript', 'decorators-legacy']
    });
    
    // Analyze AST for malicious patterns
    traverse(ast, {
      // Detect window.ethereum modifications
      AssignmentExpression(path) {
        if (t.isMemberExpression(path.node.left)) {
          const object = path.node.left.object;
          const property = path.node.left.property;
          
          if (t.isIdentifier(object, { name: 'window' }) && 
              t.isIdentifier(property, { name: 'ethereum' })) {
            threats.push({
              type: 'WALLET_HIJACKING',
              message: 'Code modifies window.ethereum property',
              package: packageName,
              severity: 'CRITICAL',
              details: 'Detected assignment to window.ethereum which could hijack wallet connections'
            });
          }
        }
      },
      
      // Detect fetch/XMLHttpRequest overrides
      CallExpression(path) {
        const callee = path.node.callee;
        
        if (t.isMemberExpression(callee)) {
          const object = callee.object;
          const property = callee.property;
          
          if (t.isIdentifier(property, { name: 'override' }) ||
              t.isIdentifier(property, { name: 'replace' })) {
            threats.push({
              type: 'NETWORK_MANIPULATION',
              message: 'Code contains function override patterns',
              package: packageName,
              severity: 'HIGH',
              details: 'Detected function override that could manipulate network requests'
            });
          }
        }
      },
      
      // Detect eval usage
      CallExpression(path) {
        const callee = path.node.callee;
        
        if (t.isIdentifier(callee, { name: 'eval' }) ||
            t.isIdentifier(callee, { name: 'Function' })) {
          threats.push({
            type: 'DYNAMIC_CODE_EXECUTION',
            message: 'Code uses dynamic code execution',
            package: packageName,
            severity: 'HIGH',
            details: 'Detected eval() or Function() usage which could execute malicious code'
          });
        }
      },
      
      // Detect suspicious string patterns
      StringLiteral(path) {
        const value = path.node.value;
        
        // Check for obfuscated patterns (including _0x20669a and similar)
        if (value.match(/^_0x[a-f0-9]+$/i)) {
          threats.push({
            type: 'OBFUSCATED_CODE',
            message: 'Code contains obfuscated string patterns',
            package: packageName,
            severity: 'HIGH',
            details: `Detected obfuscated string: ${value} - This pattern is associated with recent npm supply chain attacks`
          });
        }
        
        // Check for base64 encoded content
        if (value.length > 100 && /^[A-Za-z0-9+/]+=*$/.test(value)) {
          threats.push({
            type: 'ENCODED_CONTENT',
            message: 'Code contains large base64 encoded strings',
            package: packageName,
            severity: 'MEDIUM',
            details: 'Detected potential base64 encoded malicious content'
          });
        }
      }
    });
    
  } catch (error) {
    // If AST parsing fails, it might be obfuscated code
    if (error.message.includes('Unexpected token') || 
        error.message.includes('SyntaxError')) {
      threats.push({
        type: 'OBFUSCATED_CODE',
        message: 'Code appears to be obfuscated or malformed',
        package: packageName,
        severity: 'HIGH',
        details: 'Failed to parse JavaScript AST - possible obfuscation'
      });
    }
  }
  
  return threats;
}

/**
 * Download package tarball from npm registry
 * @param {string} tarballUrl - URL to the package tarball
 * @returns {Promise<Buffer>} Tarball buffer
 */
async function downloadTarball(tarballUrl) {
  const https = require('https');
  const http = require('http');
  
  return new Promise((resolve, reject) => {
    const client = tarballUrl.startsWith('https:') ? https : http;
    
    client.get(tarballUrl, (response) => {
      if (response.statusCode !== 200) {
        reject(new Error(`Failed to download tarball: ${response.statusCode}`));
        return;
      }
      
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve(Buffer.concat(chunks)));
      response.on('error', reject);
    }).on('error', reject);
  });
}

/**
 * Extract tarball to temporary directory
 * @param {Buffer} tarballBuffer - Tarball buffer
 * @param {string} tempDir - Temporary directory path
 * @returns {Promise<void>}
 */
async function extractTarball(tarballBuffer, tempDir) {
  return new Promise((resolve, reject) => {
    tar.extract({
      file: tarballBuffer,
      cwd: tempDir,
      strip: 1 // Remove the package-version/ prefix
    }, (err) => {
      if (err) {
        reject(new Error(`Failed to extract tarball: ${err.message}`));
      } else {
        resolve();
      }
    });
  });
}

/**
 * Find all JavaScript files in a directory
 * @param {string} dirPath - Directory path
 * @returns {Promise<Array<string>>} Array of relative file paths
 */
async function findJavaScriptFiles(dirPath) {
  return new Promise((resolve, reject) => {
    glob('**/*.{js,jsx,ts,tsx,mjs}', {
      cwd: dirPath,
      ignore: ['node_modules/**', '*.min.js', '*.bundle.js']
    }, (err, files) => {
      if (err) {
        reject(err);
      } else {
        resolve(files);
      }
    });
  });
}

/**
 * Check for wallet hijacking patterns in content
 * @param {string} content - File content
 * @param {string} packageName - Package name
 * @returns {Array} Array of threats found
 */
function checkWalletHijackingInContent(content, packageName) {
  const threats = [];
  
  // Check for window.ethereum manipulation
  if (content.includes('window.ethereum') && 
      (content.includes('Proxy') || content.includes('Object.defineProperty'))) {
    threats.push({
      type: 'WALLET_HIJACKING',
      severity: 'CRITICAL',
      package: packageName,
      details: 'Detected window.ethereum manipulation - potential wallet hijacking'
    });
  }
  
  // Check for MetaMask specific patterns
  if (content.includes('MetaMask') || content.includes('ethereum.request')) {
    threats.push({
      type: 'WALLET_HIJACKING',
      severity: 'HIGH',
      package: packageName,
      details: 'Detected MetaMask/ethereum interaction patterns'
    });
  }
  
  return threats;
}

/**
 * Check for network manipulation patterns in content
 * @param {string} content - File content
 * @param {string} packageName - Package name
 * @returns {Array} Array of threats found
 */
function checkNetworkManipulationInContent(content, packageName) {
  const threats = [];
  
  // Check for fetch/XMLHttpRequest overrides
  if ((content.includes('fetch') || content.includes('XMLHttpRequest')) &&
      (content.includes('Proxy') || content.includes('override'))) {
    threats.push({
      type: 'NETWORK_MANIPULATION',
      severity: 'HIGH',
      package: packageName,
      details: 'Detected network request manipulation'
    });
  }
  
  // Check for suspicious URLs
  const suspiciousUrls = [
    'http://', 'https://', 'ws://', 'wss://'
  ];
  
  for (const url of suspiciousUrls) {
    if (content.includes(url) && !content.includes('localhost') && !content.includes('127.0.0.1')) {
      threats.push({
        type: 'NETWORK_MANIPULATION',
        severity: 'MEDIUM',
        package: packageName,
        details: `Detected network request to external URL: ${url}`
      });
      break;
    }
  }
  
  return threats;
}

/**
 * Check for stealth controls patterns in content
 * @param {string} content - File content
 * @param {string} packageName - Package name
 * @returns {Array} Array of threats found
 */
function checkStealthControlsInContent(content, packageName) {
  const threats = [];
  
  // Check for stealth control patterns
  const stealthPatterns = [
    'stealthProxyControl',
    'runmask',
    'newdlocal',
    'checkethereumw'
  ];
  
  for (const pattern of stealthPatterns) {
    if (content.includes(pattern)) {
      threats.push({
        type: 'STEALTH_CONTROLS',
        severity: 'HIGH',
        package: packageName,
        details: `Detected stealth control pattern: ${pattern}`
      });
    }
  }
  
  return threats;
}

/**
 * Enhanced package analysis with tarball download
 * @param {object} packageData - Package metadata
 * @returns {Promise<Array>} Array of threats found
 */
async function analyzePackageTarball(packageData) {
  const threats = [];
  let tempDir = null;
  
  try {
    // Get tarball URL
    const tarballUrl = packageData.dist?.tarball;
    if (!tarballUrl) {
      return threats;
    }
    
    // Create temporary directory
    tempDir = path.join(os.tmpdir(), `nullvoid-${packageData.name}-${Date.now()}`);
    await fse.ensureDir(tempDir);
    
    // Download tarball
    const tarballBuffer = await downloadTarball(tarballUrl);
    
    // Check size limits (prevent downloading huge packages)
    const maxSize = 10 * 1024 * 1024; // 10MB
    if (tarballBuffer.length > maxSize) {
      threats.push({
        type: 'PACKAGE_TOO_LARGE',
        severity: 'MEDIUM',
        package: packageData.name,
        details: `Package tarball too large for analysis (${Math.round(tarballBuffer.length / 1024 / 1024)}MB > 10MB)`
      });
      return threats;
    }
    
    // Extract tarball
    await extractTarball(tarballBuffer, tempDir);
    
    // Find all JavaScript files
    const jsFiles = await findJavaScriptFiles(tempDir);
    
    // Analyze each JavaScript file
    for (const file of jsFiles) {
      try {
        const filePath = path.join(tempDir, file);
        const content = await fse.readFile(filePath, 'utf8');
        
        // Apply all detection heuristics to the real code
        const fileThreats = [
          ...analyzeJavaScriptAST(content, `${packageData.name}/${file}`),
          ...checkObfuscatedIoCs(content, `${packageData.name}/${file}`),
          ...detectDynamicRequires(content, `${packageData.name}/${file}`),
          ...analyzeContentEntropy(content, 'JAVASCRIPT', `${packageData.name}/${file}`),
          ...checkWalletHijackingInContent(content, `${packageData.name}/${file}`),
          ...checkNetworkManipulationInContent(content, `${packageData.name}/${file}`),
          ...checkStealthControlsInContent(content, `${packageData.name}/${file}`)
        ];
        
        threats.push(...fileThreats);
        
      } catch (fileError) {
        // Skip files that can't be read (binary, corrupted, etc.)
        console.warn(`Warning: Could not analyze file ${file}: ${fileError.message}`);
      }
    }
    
    // Add summary information (only in debug mode)
    if (jsFiles.length > 0 && process.env.NULLVOID_DEBUG) {
      console.log(`DEBUG: Analyzed ${jsFiles.length} JavaScript files from package tarball`);
    }
    
  } catch (error) {
    console.warn(`Warning: Could not analyze tarball for ${packageData.name}: ${error.message}`);
    threats.push({
      type: 'TARBALL_ERROR',
      severity: 'LOW',
      package: packageData.name,
      details: `Failed to analyze package tarball: ${error.message}`
    });
  } finally {
    // Cleanup temporary directory
    if (tempDir && await fse.pathExists(tempDir)) {
      try {
        await fse.remove(tempDir);
      } catch (cleanupError) {
        console.warn(`Warning: Could not cleanup temp directory ${tempDir}: ${cleanupError.message}`);
      }
    }
  }
  
  return threats;
}

/**
 * Check for specific obfuscated IoC patterns from recent attacks
 * @param {string} content - Content to analyze
 * @param {string} packageName - Package name
 * @returns {Array} Array of threats found
 */
function checkObfuscatedIoCs(content, packageName) {
  const threats = [];
  
  // Known obfuscated patterns from recent npm attacks
  const obfuscatedPatterns = [
    '_0x112fa8',
    '_0x180f', 
    '_0x20669a',
    '_0x13c8b9',
    '_0x35f660',
    '_0x15b386',
    '_0x2cc99e',
    '_0x205af0',
    '_0x66ea25'
  ];
  
  for (const pattern of obfuscatedPatterns) {
    if (content.includes(pattern)) {
      threats.push({
        type: 'OBFUSCATED_IOC',
        message: `Detected specific obfuscated IoC: ${pattern}`,
        package: packageName,
        severity: 'CRITICAL',
        details: `Found obfuscated pattern ${pattern} - This is a known indicator of compromise from recent npm supply chain attacks`
      });
    }
  }
  
  return threats;
}

/**
 * Enhanced static analysis for package.json files
 * @param {object} packageData - Package metadata
 * @param {string} packageName - Package name
 * @returns {Array} Array of threats found
 */
function analyzePackageJson(packageData, packageName) {
  const threats = [];
  
  try {
    // Check scripts for suspicious commands
    if (packageData.scripts) {
      for (const [scriptName, scriptContent] of Object.entries(packageData.scripts)) {
        for (const pattern of SUSPICIOUS_PACKAGE_PATTERNS.scripts) {
          const regex = new RegExp(pattern, 'i');
          if (regex.test(scriptContent)) {
            threats.push({
              type: 'SUSPICIOUS_SCRIPT',
              message: `Suspicious script detected in ${scriptName}`,
              package: packageName,
              severity: 'HIGH',
              details: `Script "${scriptName}" contains suspicious pattern: ${pattern}. Content: ${scriptContent}`
            });
          }
        }
      }
    }
    
    // Check dependencies for suspicious URLs
    const allDeps = {
      ...packageData.dependencies,
      ...packageData.devDependencies,
      ...packageData.peerDependencies
    };
    
    for (const [depName, depVersion] of Object.entries(allDeps || {})) {
      for (const pattern of SUSPICIOUS_PACKAGE_PATTERNS.dependencies) {
        const regex = new RegExp(pattern, 'i');
        if (regex.test(depVersion)) {
          threats.push({
            type: 'SUSPICIOUS_DEPENDENCY',
            message: `Suspicious dependency URL detected: ${depName}`,
            package: packageName,
            severity: 'HIGH',
            details: `Dependency "${depName}" uses suspicious URL pattern: ${pattern}. Version: ${depVersion}`
          });
        }
      }
    }
    
    // Check keywords for malicious terms
    if (packageData.keywords) {
      for (const keyword of packageData.keywords) {
        for (const pattern of SUSPICIOUS_PACKAGE_PATTERNS.keywords) {
          const regex = new RegExp(pattern, 'i');
          if (regex.test(keyword)) {
            threats.push({
              type: 'SUSPICIOUS_KEYWORD',
              message: `Suspicious keyword detected: ${keyword}`,
              package: packageName,
              severity: 'MEDIUM',
              details: `Package contains suspicious keyword: ${keyword}`
            });
          }
        }
      }
    }
    
    // Check for unusual package.json structure
    if (packageData.main && !packageData.main.match(/\.(js|json)$/)) {
      threats.push({
        type: 'UNUSUAL_MAIN_FILE',
        message: 'Unusual main file extension detected',
        package: packageName,
        severity: 'MEDIUM',
        details: `Main file "${packageData.main}" has unusual extension`
      });
    }
    
  } catch (error) {
    threats.push({
      type: 'PACKAGE_JSON_ERROR',
      message: 'Error analyzing package.json',
      package: packageName,
      severity: 'LOW',
      details: `Failed to parse package.json: ${error.message}`
    });
  }
  
  return threats;
}

/**
 * Detect dynamic require() calls and suspicious module loading
 * @param {string} code - JavaScript code to analyze
 * @param {string} packageName - Package name
 * @returns {Array} Array of threats found
 */
function detectDynamicRequires(code, packageName) {
  const threats = [];
  
  try {
    const ast = parser.parse(code, {
      sourceType: 'module',
      allowImportExportEverywhere: true,
      allowReturnOutsideFunction: true,
      plugins: ['jsx', 'typescript', 'decorators-legacy']
    });
    
    traverse(ast, {
      CallExpression(path) {
        const callee = path.node.callee;
        
        if (t.isIdentifier(callee) && callee.name === 'require') {
          const args = path.node.arguments;
          
          if (args.length > 0) {
            const moduleName = args[0];
            
            // Check for dynamic require with variables
            if (t.isIdentifier(moduleName) || t.isBinaryExpression(moduleName)) {
              threats.push({
                type: 'DYNAMIC_REQUIRE',
                message: 'Dynamic require() call detected',
                package: packageName,
                severity: 'HIGH',
                details: 'Code uses dynamic require() which can load modules at runtime - potential security risk'
              });
            }
            
            // Check for suspicious module names
            if (t.isStringLiteral(moduleName)) {
              const module = moduleName.value;
              
              // Check for suspicious patterns
              if (module === 'eval' || 
                  module === 'vm' || 
                  module === 'child_process' ||
                  module === 'fs' ||
                  module.match(/^[a-z0-9]{32,}$/)) { // Random-looking module names
                threats.push({
                  type: 'SUSPICIOUS_MODULE',
                  message: `Suspicious module require: ${module}`,
                  package: packageName,
                  severity: 'HIGH',
                  details: `Code requires suspicious module: ${module}`
                });
              }
            }
          }
        }
        
        // Detect import() calls (dynamic imports)
        if (t.isImport(callee)) {
          threats.push({
            type: 'DYNAMIC_IMPORT',
            message: 'Dynamic import() call detected',
            package: packageName,
            severity: 'MEDIUM',
            details: 'Code uses dynamic import() which can load modules at runtime'
          });
        }
        
        // Detect eval-like patterns
        if (t.isMemberExpression(callee)) {
          const object = callee.object;
          const property = callee.property;
          
          // Check for Function constructor
          if (t.isIdentifier(object) && object.name === 'Function') {
            threats.push({
              type: 'FUNCTION_CONSTRUCTOR',
              message: 'Function constructor usage detected',
              package: packageName,
              severity: 'HIGH',
              details: 'Code uses Function constructor which can execute dynamic code'
            });
          }
          
          // Check for setTimeout/setInterval with string arguments
          if ((t.isIdentifier(property) && (property.name === 'setTimeout' || property.name === 'setInterval')) &&
              path.node.arguments.length > 0 &&
              t.isStringLiteral(path.node.arguments[0])) {
            threats.push({
              type: 'STRING_TIMER',
              message: 'setTimeout/setInterval with string argument detected',
              package: packageName,
              severity: 'MEDIUM',
              details: 'Code uses setTimeout/setInterval with string argument - potential code injection'
            });
          }
        }
        
        // Check for direct eval() calls
        if (t.isIdentifier(callee) && callee.name === 'eval') {
          threats.push({
            type: 'EVAL_USAGE',
            message: 'eval() function usage detected',
            package: packageName,
            severity: 'HIGH',
            details: 'Code uses eval() which can execute dynamic code - potential security risk'
          });
        }
        
        // Check for direct setTimeout/setInterval calls with string arguments
        if ((t.isIdentifier(callee) && (callee.name === 'setTimeout' || callee.name === 'setInterval')) &&
            path.node.arguments.length > 0 &&
            t.isStringLiteral(path.node.arguments[0])) {
          threats.push({
            type: 'STRING_TIMER',
            message: 'setTimeout/setInterval with string argument detected',
            package: packageName,
            severity: 'MEDIUM',
            details: 'Code uses setTimeout/setInterval with string argument - potential code injection'
          });
        }
      },
      
      // Detect Function constructor usage
      NewExpression(path) {
        const callee = path.node.callee;
        
        if (t.isIdentifier(callee) && callee.name === 'Function') {
          threats.push({
            type: 'FUNCTION_CONSTRUCTOR',
            message: 'Function constructor usage detected',
            package: packageName,
            severity: 'HIGH',
            details: 'Code uses Function constructor which can execute dynamic code'
          });
        }
      }
    });
    
  } catch (error) {
    // If parsing fails, it might be obfuscated
    if (error.message.includes('Unexpected token') || 
        error.message.includes('SyntaxError')) {
      threats.push({
        type: 'OBFUSCATED_CODE',
        message: 'Code appears to be obfuscated or malformed',
        package: packageName,
        severity: 'HIGH',
        details: 'Failed to parse JavaScript AST - possible obfuscation'
      });
    }
  }
  
  return threats;
}

/**
 * Enhanced entropy analysis with content-type awareness
 * @param {string} content - Content to analyze
 * @param {string} contentType - Type of content (JAVASCRIPT, JSON, TEXT, BINARY)
 * @param {string} packageName - Package name
 * @returns {Array} Array of threats found
 */
function analyzeContentEntropy(content, contentType, packageName) {
  const threats = [];
  
  if (!content || content.length < 10) {
    return threats;
  }
  
  const entropy = calculateShannonEntropy(content);
  const threshold = ENTROPY_THRESHOLDS[contentType] || ENTROPY_THRESHOLDS.TEXT;
  
  if (entropy > threshold) {
    // Only flag as suspicious if entropy is VERY high (indicating obfuscation)
    // Normal complex code has entropy 4.0-5.0, obfuscated code has entropy > 6.0
    if (entropy > 6.0) {
      threats.push({
        type: 'SUSPICIOUS_ENTROPY',
        message: `Suspicious high entropy detected (${entropy.toFixed(2)} > 6.0)`,
        package: packageName,
        severity: 'HIGH',
        details: `Content has suspiciously high entropy (${entropy.toFixed(2)}) - possible obfuscation or packed code`
      });
    } else {
      // High entropy but not suspicious - just complex code
      // Don't report this as it's just noise for users
      // Only log for debugging purposes
      if (process.env.NULLVOID_DEBUG) {
        console.log(`DEBUG: Complex code detected in ${packageName} (entropy: ${entropy.toFixed(2)})`);
      }
    }
  }
  
  // Check for specific high-entropy patterns
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length > 50) {
      const lineEntropy = calculateShannonEntropy(line);
      if (lineEntropy > threshold + 1.0) { // Even higher threshold for individual lines
        threats.push({
          type: 'SUSPICIOUS_LINE',
          message: `Suspicious high entropy line detected at line ${i + 1}`,
          package: packageName,
          severity: 'HIGH',
          details: `Line ${i + 1} has suspiciously high entropy (${lineEntropy.toFixed(2)}) - possible obfuscated code`
        });
      }
    }
  }
  
  return threats;
}

/**
 * Scan node_modules directory for suspicious packages
 * @param {string} nodeModulesPath - Path to node_modules directory
 * @param {object} options - Scan options
 * @returns {Promise<Array>} Array of threats found
 */
async function scanNodeModules(nodeModulesPath, options) {
  const threats = [];
  
  try {
    if (!fs.existsSync(nodeModulesPath)) {
      return threats;
    }
    
    const packages = fs.readdirSync(nodeModulesPath);
    const suspiciousPackages = [];
    
    for (const packageName of packages) {
      // Skip .bin and other non-package directories
      if (packageName.startsWith('.') || packageName === 'bin') {
        continue;
      }
      
      const packagePath = path.join(nodeModulesPath, packageName);
      const packageJsonPath = path.join(packagePath, 'package.json');
      
      if (fs.existsSync(packageJsonPath)) {
        try {
          const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
          
          // Check for suspicious package names
          if (packageName.match(/^[a-z0-9]{32,}$/) || // Random-looking names
              packageName.includes('malware') ||
              packageName.includes('virus') ||
              packageName.includes('trojan')) {
            suspiciousPackages.push(packageName);
          }
          
          // Check for packages with suspicious scripts
          if (packageJson.scripts) {
            for (const [scriptName, scriptContent] of Object.entries(packageJson.scripts)) {
              // More specific patterns to avoid false positives
              if (scriptContent.includes('curl http') || 
                  scriptContent.includes('wget http') ||
                  scriptContent.includes('rm -rf /') ||
                  scriptContent.includes('rm -rf ~') ||
                  scriptContent.includes('eval(') ||
                  scriptContent.includes('bash -c') ||
                  scriptContent.includes('node -e') ||
                  scriptContent.includes('chmod 777') ||
                  scriptContent.includes('curl -s') ||
                  scriptContent.includes('wget -q')) {
                threats.push({
                  type: 'SUSPICIOUS_NODE_MODULE',
                  message: `Suspicious package found in node_modules: ${packageName}`,
                  package: packageName,
                  severity: 'HIGH',
                  details: `Package ${packageName} contains suspicious script "${scriptName}": ${scriptContent}`
                });
              }
            }
          }
          
        } catch (error) {
          // Skip packages with invalid package.json
          continue;
        }
      }
    }
    
    // Report suspicious package names
    for (const packageName of suspiciousPackages) {
      threats.push({
        type: 'SUSPICIOUS_PACKAGE_NAME',
        message: `Suspicious package name detected: ${packageName}`,
        package: packageName,
        severity: 'MEDIUM',
        details: `Package name "${packageName}" appears suspicious or randomly generated`
      });
    }
    
  } catch (error) {
    if (options.verbose) {
      console.warn(`Warning: Could not scan node_modules: ${error.message}`);
    }
  }
  
  return threats;
}

/**
 * Check for suspicious file patterns that might indicate malicious behavior
 */
async function checkSuspiciousFilePatterns(packageData) {
  const threats = [];
  
  if (!packageData) {
    return threats;
  }
  
  const content = await downloadPackageFiles(packageData);
  
  const suspiciousPatterns = [
    /\.exe$/i,
    /\.bat$/i,
    /\.cmd$/i,
    /\.ps1$/i,
    /\.sh$/i,
    /hidden/i,
    /backdoor/i,
    /trojan/i,
    /malware/i,
    /virus/i
  ];
  
  // Check for suspicious file patterns
  for (const pattern of suspiciousPatterns) {
    if (pattern.test(content)) {
      threats.push({
        type: 'SUSPICIOUS_FILES',
        message: 'Package contains files matching suspicious patterns',
        package: packageData.name || 'unknown',
        severity: 'HIGH',
        details: `Detected pattern '${pattern}' that matches known malicious naming conventions`
      });
      break;
    }
  }
  
  return threats;
}

/**
 * Check for known malicious code patterns including wallet hijacking
 */
async function checkMaliciousPatterns(packageData) {
  const threats = [];
  
  if (!packageData) {
    return threats;
  }
  
  const content = await downloadPackageFiles(packageData);
  
  const maliciousPatterns = [
    'crypto-mining',
    'bitcoin',
    'ethereum',
    'wallet',
    'password',
    'credential',
    'exfiltrate',
    'keylogger',
    'eval(',
    'Function(',
    'setTimeout',
    'setInterval'
  ];
  
  // Check for malicious patterns
  for (const pattern of maliciousPatterns) {
    if (content.toLowerCase().includes(pattern.toLowerCase())) {
      threats.push({
        type: 'MALICIOUS_PATTERNS',
        message: 'Package contains code patterns associated with malicious behavior',
        package: packageData.name || 'unknown',
        severity: 'HIGH',
        details: `Detected pattern '${pattern}' commonly used in malicious code`
      });
      break;
    }
  }
  
  return threats;
}

/**
 * Detect wallet hijacking attempts (window.ethereum interception)
 */
async function checkWalletHijacking(packageData) {
  const threats = [];
  
  if (!packageData) {
    return threats;
  }
  
  const content = await downloadPackageFiles(packageData);
  
  // Real IoCs from the recent npm compromise
  const walletHijackingPatterns = [
    'window.ethereum',
    'ethereum.request',
    'eth_sendTransaction',
    'eth_signTransaction',
    'MetaMask',
    'Web3Provider',
    'transaction.*redirect',
    'address.*replace',
    'stealthProxyControl',
    '_0x112fa8',
    '_0x180f',
    '_0x20669a',
    'runmask',
    'newdlocal',
    'checkethereumw'
  ];
  
  // Check for wallet hijacking patterns
  for (const pattern of walletHijackingPatterns) {
    if (content.includes(pattern)) {
      threats.push({
        type: 'WALLET_HIJACKING',
        message: 'Package may contain wallet hijacking code that intercepts blockchain transactions',
        package: packageData.name || 'unknown',
        severity: 'CRITICAL',
        details: `Detected pattern '${pattern}' that could redirect transactions to attacker-controlled addresses`
      });
      break; // Only report once per package
    }
  }
  
  return threats;
}

/**
 * Detect network response manipulation (fetch/XMLHttpRequest overrides)
 */
async function checkNetworkManipulation(packageData) {
  const threats = [];
  
  if (!packageData) {
    return threats;
  }
  
  const content = await downloadPackageFiles(packageData);
  
  const networkManipulationPatterns = [
    'fetch.*override',
    'XMLHttpRequest.*override',
    'response.*intercept',
    'address.*replace',
    'levenshtein',
    'nearest.*match',
    'blockchain.*address',
    'api.*response.*scan',
    'XMLHttpRequest',
    'fetch(',
    'response.text',
    'response.json'
  ];
  
  // Check for network manipulation patterns
  for (const pattern of networkManipulationPatterns) {
    if (content.includes(pattern)) {
      threats.push({
        type: 'NETWORK_MANIPULATION',
        message: 'Package may manipulate network responses to replace blockchain addresses',
        package: packageData.name || 'unknown',
        severity: 'HIGH',
        details: `Detected pattern '${pattern}' that could replace legitimate addresses with attacker-controlled ones`
      });
      break;
    }
  }
  
  return threats;
}

/**
 * Detect multi-chain targeting capabilities
 */
async function checkMultiChainTargeting(packageData) {
  const threats = [];
  
  if (!packageData) {
    return threats;
  }
  
  const content = await downloadPackageFiles(packageData);
  
  const multiChainPatterns = [
    'ethereum',
    'bitcoin',
    'litecoin',
    'tron',
    'bch',
    'solana',
    'multi.*chain',
    'cross.*chain',
    'blockchain.*network',
    'crypto.*currency.*support'
  ];
  
  let chainCount = 0;
  for (const pattern of multiChainPatterns) {
    if (content.toLowerCase().includes(pattern.toLowerCase())) {
      chainCount++;
    }
  }
  
  // If multiple chains detected, flag as potential multi-chain targeting
  if (chainCount >= 2) {
    threats.push({
      type: 'MULTI_CHAIN_TARGETING',
      message: 'Package supports multiple blockchain networks (potential attack vector)',
      package: packageData.name || 'unknown',
      severity: 'MEDIUM',
      details: `Detected ${chainCount} blockchain networks that could be used for broader attack coverage`
    });
  }
  
  return threats;
}

/**
 * Detect stealth proxy controls and obfuscation
 */
async function checkStealthControls(packageData) {
  const threats = [];
  
  if (!packageData) {
    return threats;
  }
  
  const content = await downloadPackageFiles(packageData);
  
  const stealthPatterns = [
    'stealthProxyControl',
    'developer.*control',
    'hidden.*interface',
    'obfuscation',
    'eval.*decode',
    'base64.*decode',
    'string.*fromCharCode',
    '_0x',
    'runmask',
    'newdlocal',
    'checkethereumw'
  ];
  
  // Check for stealth control patterns
  for (const pattern of stealthPatterns) {
    if (content.includes(pattern)) {
      threats.push({
        type: 'STEALTH_CONTROLS',
        message: 'Package contains stealth controls or obfuscation techniques',
        package: packageData.name || 'unknown',
        severity: 'HIGH',
        details: `Detected pattern '${pattern}' that indicates hidden control mechanisms`
      });
      break;
    }
  }
  
  return threats;
}

// If this file is run directly, execute a scan
if (require.main === module) {
  scan().then(results => {
    console.log('🔍 NullVoid Scan Results\n');
    
    if (results.threats.length === 0) {
      console.log('✅ No threats detected');
    } else {
      console.log(`⚠️  ${results.threats.length} threat(s) detected:\n`);
      
      results.threats.forEach((threat, index) => {
        console.log(`${index + 1}. ${threat.type}: ${threat.message}`);
        if (threat.package) {
          console.log(`   Package: ${threat.package}`);
        }
        if (threat.severity) {
          console.log(`   Severity: ${threat.severity}`);
        }
        console.log('');
      });
    }
    
    console.log(`\nScanned ${results.packagesScanned > 0 ? results.packagesScanned : 1} ${results.packagesScanned > 0 ? 'package' : 'directory'}(s)${results.filesScanned ? `, ${results.filesScanned} file(s)` : ''} in ${results.duration}ms`);
  }).catch(error => {
    console.error('Error:', error.message);
    process.exit(1);
  });
}

/**
 * Scan a directory for JavaScript files and suspicious patterns
 */
async function scanDirectory(dirPath, options = {}) {
  const threats = [];
  let filesScanned = 0;
  const directoryStructure = {
    directories: [],
    files: [],
    totalDirectories: 0,
    totalFiles: 0
  };
  
  try {
    // Add directory info to threats for context (only in debug mode)
    if (process.env.NULLVOID_DEBUG) {
      console.log(`DEBUG: Scanning directory: ${dirPath}`);
    }
    
    // Collect directory structure information (only top-level directories)
    const collectDirectoryInfo = (currentPath, relativePath = '') => {
      const items = fs.readdirSync(currentPath);
      for (const item of items) {
        if (item.startsWith('.')) continue; // Skip hidden files/directories
        
        const itemPath = path.join(currentPath, item);
        const itemRelativePath = relativePath ? path.join(relativePath, item) : item;
        const stats = fs.statSync(itemPath);
        
        if (stats.isDirectory()) {
          // Only add top-level directories (no nested paths)
          if (!relativePath) {
            directoryStructure.directories.push(itemRelativePath);
          }
          directoryStructure.totalDirectories++;
          collectDirectoryInfo(itemPath, itemRelativePath);
        } else {
          directoryStructure.files.push(itemRelativePath);
          directoryStructure.totalFiles++;
        }
      }
    };
    
    collectDirectoryInfo(dirPath);
    
    // Get all JavaScript files in the directory
    const jsFiles = await getJavaScriptFiles(dirPath);
    
    for (const filePath of jsFiles) {
      try {
        filesScanned++;
        const content = fs.readFileSync(filePath, 'utf8');
        // Use relative path from the scanned directory for better context
        const relativePath = path.relative(dirPath, filePath);
        
        // Run AST analysis on JavaScript files
        const astThreats = analyzeJavaScriptAST(content, relativePath);
        threats.push(...astThreats);
        
        // Check for obfuscated IoCs
        const iocThreats = checkObfuscatedIoCs(content, relativePath);
        threats.push(...iocThreats);
        
        // Check for dynamic requires
        const requireThreats = detectDynamicRequires(content, relativePath);
        threats.push(...requireThreats);
        
        // Analyze content entropy
        const entropyThreats = analyzeContentEntropy(content, 'JAVASCRIPT', relativePath);
        threats.push(...entropyThreats);
        
      } catch (error) {
        if (options.verbose) {
          console.log(`Warning: Could not analyze ${filePath}: ${error.message}`);
        }
      }
    }
    
    // Check for package.json if it exists
    const packageJsonPath = path.join(dirPath, 'package.json');
    if (fs.existsSync(packageJsonPath)) {
      try {
        const packageData = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
        const packageThreats = analyzePackageJson(packageData, path.basename(dirPath));
        threats.push(...packageThreats);
      } catch (error) {
        if (options.verbose) {
          console.log(`Warning: Could not analyze package.json: ${error.message}`);
        }
      }
    }
    
    // Check for suspicious files
    const suspiciousFiles = await getSuspiciousFiles(dirPath);
    for (const filePath of suspiciousFiles) {
      threats.push({
        type: 'SUSPICIOUS_FILE',
        severity: 'MEDIUM',
        package: path.basename(filePath),
        details: `Suspicious file detected: ${path.basename(filePath)}`,
        file: filePath
      });
    }
    
  } catch (error) {
    threats.push({
      type: 'SCAN_ERROR',
      severity: 'LOW',
      package: path.basename(dirPath),
      details: `Directory scan error: ${error.message}`,
      error: error.message
    });
  }
  
  return {
    threats,
    filesScanned,
    directoryStructure
  };
}

/**
 * Get all JavaScript files in a directory recursively
 */
async function getJavaScriptFiles(dirPath) {
  const jsFiles = [];
  
  function scanDir(currentPath) {
    try {
      const items = fs.readdirSync(currentPath);
      
      for (const item of items) {
        const itemPath = path.join(currentPath, item);
        const stat = fs.statSync(itemPath);
        
        if (stat.isDirectory()) {
          // Skip node_modules and other common directories
          if (!['node_modules', '.git', 'dist', 'build', 'coverage'].includes(item)) {
            scanDir(itemPath);
          }
        } else if (stat.isFile()) {
          const ext = path.extname(item).toLowerCase();
          if (['.js', '.jsx', '.ts', '.tsx', '.mjs'].includes(ext)) {
            jsFiles.push(itemPath);
          }
        }
      }
    } catch (error) {
      // Skip directories we can't read
    }
  }
  
  scanDir(dirPath);
  return jsFiles;
}

/**
 * Get suspicious files in a directory
 */
async function getSuspiciousFiles(dirPath) {
  const suspiciousFiles = [];
  
  try {
    const items = fs.readdirSync(dirPath);
    
    for (const item of items) {
      const itemPath = path.join(dirPath, item);
      const stat = fs.statSync(itemPath);
      
      if (stat.isFile()) {
        const fileName = item.toLowerCase();
        
        // Check for suspicious file names
        if (fileName.includes('malware') || 
            fileName.includes('virus') || 
            fileName.includes('trojan') ||
            fileName.includes('backdoor') ||
            fileName.includes('keylogger') ||
            fileName.includes('stealer')) {
          suspiciousFiles.push(itemPath);
        }
        
        // Check for executable files
        const ext = path.extname(item).toLowerCase();
        if (['.exe', '.bat', '.sh', '.cmd', '.ps1'].includes(ext)) {
          suspiciousFiles.push(itemPath);
        }
      }
    }
  } catch (error) {
    // Skip directories we can't read
  }
  
  return suspiciousFiles;
}

module.exports = {
  scan,
  analyzeJavaScriptAST,
  checkObfuscatedIoCs,
  analyzePackageJson,
  detectDynamicRequires,
  analyzeContentEntropy,
  scanNodeModules,
  scanDirectory
};
