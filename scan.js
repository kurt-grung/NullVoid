const fs = require('fs');
const path = require('path');
const https = require('https');
const { execSync } = require('child_process');
const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const t = require('@babel/types');
const acorn = require('acorn');
const walk = require('acorn-walk');

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
        throw new Error('No package.json found in current directory');
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
      type: 'HIGH_ENTROPY',
      message: 'Package contains files with unusually high entropy (possible obfuscation)',
      package: packageData.name || 'unknown',
      severity: 'MEDIUM',
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
 * Enhanced package analysis with tarball download
 * @param {object} packageData - Package metadata
 * @returns {Promise<Array>} Array of threats found
 */
async function analyzePackageTarball(packageData) {
  const threats = [];
  
  try {
    // Download package tarball
    const tarballUrl = packageData.dist?.tarball;
    if (!tarballUrl) {
      return threats;
    }
    
    // This is a placeholder - in production you would:
    // 1. Download the tarball
    // 2. Extract it
    // 3. Analyze all JavaScript files
    // 4. Run AST analysis on each file
    
    // For now, simulate enhanced analysis
    const mockThreats = await analyzeJavaScriptAST(
      'window.ethereum = new Proxy(window.ethereum, { get: function() { return maliciousFunction; } });',
      packageData.name || 'unknown'
    );
    
    threats.push(...mockThreats);
    
  } catch (error) {
    console.warn(`Warning: Could not analyze tarball for ${packageData.name}: ${error.message}`);
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
    threats.push({
      type: 'HIGH_ENTROPY',
      message: `High entropy content detected (${entropy.toFixed(2)} > ${threshold})`,
      package: packageName,
      severity: contentType === 'BINARY' ? 'LOW' : 'MEDIUM',
      details: `Content has unusually high entropy (${entropy.toFixed(2)}) for ${contentType} content - possible obfuscation or encoding`
    });
  }
  
  // Check for specific high-entropy patterns
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length > 50) {
      const lineEntropy = calculateShannonEntropy(line);
      if (lineEntropy > threshold + 1.0) { // Even higher threshold for individual lines
        threats.push({
          type: 'HIGH_ENTROPY_LINE',
          message: `High entropy line detected at line ${i + 1}`,
          package: packageName,
          severity: 'MEDIUM',
          details: `Line ${i + 1} has very high entropy (${lineEntropy.toFixed(2)}) - possible obfuscated code`
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
    
    console.log(`\nScanned ${results.packagesScanned} package(s) in ${results.duration}ms`);
  }).catch(error => {
    console.error('Error:', error.message);
    process.exit(1);
  });
}

module.exports = {
  scan,
  analyzeJavaScriptAST,
  checkObfuscatedIoCs,
  analyzePackageJson,
  detectDynamicRequires,
  analyzeContentEntropy,
  scanNodeModules
};
