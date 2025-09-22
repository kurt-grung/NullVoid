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

// Simple performance monitoring
const performanceMetrics = {
  startTime: null,
  packagesScanned: 0,
  cacheHits: 0,
  cacheMisses: 0,
  networkRequests: 0,
  errors: 0
};

// Enhanced entropy thresholds for different content types
const ENTROPY_THRESHOLDS = {
  JAVASCRIPT: 5.0,    // Higher threshold for JS (more random)
  JSON: 4.2,          // Higher threshold for JSON
  TEXT: 4.0,          // Higher threshold for general text
  BINARY: 7.5         // Higher threshold for binary/encoded content
};

// Suspicious package.json patterns
const SUSPICIOUS_PACKAGE_PATTERNS = {
  scripts: [
    'curl.*http',
    'wget.*http', 
    'rm -rf /',
    'rm -rf ~',
    'chmod.*777',
    'eval\\(.*\\)',  // More specific eval pattern
    'node -e.*http', // Only flag node -e with http requests
    'bash -c.*curl',
    'bash -c.*wget',
    'bash -c.*rm',
    'bash -c.*chmod'
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
    performanceMetrics.cacheHits++;
    return cached.data;
  }
  performanceMetrics.cacheMisses++;
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
  let dependencyTree = null;
  let performanceData = null;

  // Reset performance metrics
  performanceMetrics.startTime = startTime;
  performanceMetrics.packagesScanned = 0;
  performanceMetrics.cacheHits = 0;
  performanceMetrics.cacheMisses = 0;
  performanceMetrics.networkRequests = 0;
  performanceMetrics.errors = 0;

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
        
        // Build dependency tree and scan all transitive dependencies
        const maxDepth = options.maxDepth || 3; // Default to 3 levels deep
        const treeResult = await buildAndScanDependencyTree(dependencies, maxDepth, options, 'root');
        threats.push(...treeResult.threats);
        packagesScanned = treeResult.packagesScanned;
        dependencyTree = treeResult.tree;
        
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
      // Check if packageName is a directory path
      const fs = require('fs');
      const path = require('path');
      
      if (fs.existsSync(packageName) && fs.statSync(packageName).isDirectory()) {
        // Scan directory for package.json files and suspicious patterns
        const directoryResult = await scanDirectory(packageName, options);
        threats.push(...directoryResult.threats);
        filesScanned = directoryResult.filesScanned;
        packagesScanned = directoryResult.packagesScanned || 0;
        directoryStructure = directoryResult.directoryStructure;
        
        // Also scan any package.json files found in the directory
        const packageJsonPath = path.join(packageName, 'package.json');
        if (fs.existsSync(packageJsonPath)) {
          const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
          const dependencies = {
            ...packageJson.dependencies,
            ...packageJson.devDependencies
          };
          
          if (Object.keys(dependencies).length > 0) {
            const maxDepth = options.maxDepth || 3;
            const treeResult = await buildAndScanDependencyTree(dependencies, maxDepth, options, 'root');
            threats.push(...treeResult.threats);
            packagesScanned += treeResult.packagesScanned;
            dependencyTree = treeResult.tree;
          }
        }
      } else {
        // Scan specific package with dependency tree analysis
        const maxDepth = options.maxDepth || 3;
        const treeResult = await buildAndScanDependencyTree({ [packageName]: 'latest' }, maxDepth, options, null);
        threats.push(...treeResult.threats);
        packagesScanned = treeResult.packagesScanned;
        dependencyTree = treeResult.tree;
      }
    }

    // Get performance metrics
    const endTime = Date.now();
    const duration = endTime - startTime;
    
    performanceData = {
      packagesScanned: performanceMetrics.packagesScanned,
      cacheHits: performanceMetrics.cacheHits,
      cacheMisses: performanceMetrics.cacheMisses,
      cacheHitRate: performanceMetrics.cacheHits / (performanceMetrics.cacheHits + performanceMetrics.cacheMisses) || 0,
      networkRequests: performanceMetrics.networkRequests,
      errors: performanceMetrics.errors,
      packagesPerSecond: performanceMetrics.packagesScanned / (duration / 1000) || 0,
      duration: duration
    };
    
    return {
      threats,
      packagesScanned,
      filesScanned,
      directoryStructure,
      dependencyTree,
      performance: performanceData,
      duration: duration,
      timestamp: new Date().toISOString()
    };
  } catch (error) {
    throw new Error(`Scan failed: ${error.message}`);
  }
}

/**
 * Analyze dependency tree for hidden threats and suspicious patterns
 * @param {object} tree - Dependency tree structure
 * @param {object} options - Scan options
 * @returns {Array} Array of additional threats found
 */
function analyzeDependencyTree(tree, options) {
  const threats = [];
  
  // Analyze tree structure for suspicious patterns
  const packageNames = Object.keys(tree);
  const suspiciousPackages = [];
  const deepDependencies = [];
  
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
        threatCount: packageInfo.threats.length
      });
    }
    
    // Check for packages with many transitive dependencies (potential attack vectors)
    const depCount = packageInfo.dependencies ? Object.keys(packageInfo.dependencies).length : 0;
    
    // Higher thresholds for popular frameworks and libraries
    const popularFrameworks = ['express', 'react', 'vue', 'angular', 'next', 'nuxt', 'svelte', 'webpack', 'babel', 'typescript', 'lodash', 'moment', 'axios', 'jquery'];
    const isPopularFramework = popularFrameworks.some(framework => packageName.toLowerCase().includes(framework));
    
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
      message: `Suspicious package name detected: ${packageName}`,
      package: packageName,
      severity: 'HIGH',
      details: `Package name "${packageName}" appears suspicious or randomly generated`
    });
  }
  
  // Report deep dependencies with threats
  const deepThreats = deepDependencies.filter(dep => dep.threatCount > 0);
  if (deepThreats.length > 0) {
    threats.push({
      type: 'DEEP_DEPENDENCY_THREATS',
      message: `Threats found in deep dependency chain`,
      package: 'dependency-tree',
      severity: 'HIGH',
      details: `Found ${deepThreats.length} packages with threats at depth 2+: ${deepThreats.map(d => `${d.name} (depth ${d.depth})`).join(', ')}`
    });
  }
  
  // Check for circular dependencies (potential attack vectors)
  const circularDeps = detectCircularDependencies(tree);
  if (circularDeps.length > 0) {
    threats.push({
      type: 'CIRCULAR_DEPENDENCIES',
      message: `Circular dependencies detected`,
      package: 'dependency-tree',
      severity: 'MEDIUM',
      details: `Found circular dependencies: ${circularDeps.join(', ')}`
    });
  }
  
  return threats;
}

/**
 * Detect circular dependencies in the tree
 * @param {object} tree - Dependency tree
 * @returns {Array} Array of circular dependency chains
 */
function detectCircularDependencies(tree) {
  const circular = [];
  const visited = new Set();
  const recursionStack = new Set();
  
  function dfs(packageName, path) {
    if (recursionStack.has(packageName)) {
      // Found a cycle
      const cycleStart = path.indexOf(packageName);
      const cycle = path.slice(cycleStart).concat(packageName);
      circular.push(cycle.join(' -> '));
      return;
    }
    
    if (visited.has(packageName)) {
      return;
    }
    
    visited.add(packageName);
    recursionStack.add(packageName);
    
    const packageInfo = tree[packageName];
    if (packageInfo && packageInfo.dependencies) {
      for (const depName of Object.keys(packageInfo.dependencies)) {
        dfs(depName, [...path, packageName]);
      }
    }
    
    recursionStack.delete(packageName);
  }
  
  for (const packageName of Object.keys(tree)) {
    if (!visited.has(packageName)) {
      dfs(packageName, []);
    }
  }
  
  return circular;
}

/**
 * Build and scan dependency tree for transitive dependencies
 * @param {object} dependencies - Direct dependencies from package.json
 * @param {number} maxDepth - Maximum depth to traverse
 * @param {object} options - Scan options
 * @returns {Promise<object>} Tree scan results
 */
async function buildAndScanDependencyTree(dependencies, maxDepth, options, rootPackage = null) {
  const threats = [];
  const tree = {};
  const scannedPackages = new Set();
  let packagesScanned = 0;

  // Process dependencies level by level
  let currentLevel = Object.entries(dependencies).map(([name, version]) => ({
    name,
    version,
    path: rootPackage && rootPackage !== name ? `${rootPackage} → ${name}` : name
  }));
  let depth = 0;

  while (currentLevel.length > 0 && depth < maxDepth) {
    const nextLevel = [];
    
    for (const packageInfo of currentLevel) {
      const { name: packageName, version, path: packagePath } = packageInfo;
      
      // Skip if already scanned (avoid circular dependencies)
      const packageKey = `${packageName}@${version}`;
      if (scannedPackages.has(packageKey)) {
        continue;
      }
      
      scannedPackages.add(packageKey);
      
      // Initialize tree structure
      if (!tree[packageName]) {
        tree[packageName] = {
          version: version || 'unknown',
          depth,
          threats: [],
          dependencies: {}
        };
      }
      
      // Scan the package
      const packageThreats = await scanPackage(packageName, version, options, packagePath);
      threats.push(...packageThreats);
      tree[packageName].threats = packageThreats;
      packagesScanned++;
      
      // Get package dependencies for next level
      try {
        const packageData = await getPackageMetadata(packageName, version);
        if (packageData && packageData.dependencies) {
          const packageDeps = Object.entries(packageData.dependencies);
          tree[packageName].dependencies = Object.fromEntries(packageDeps);
          
          // Add to next level if not already scanned
          for (const [depName, depVersion] of packageDeps) {
            const depKey = `${depName}@${depVersion || 'unknown'}`;
            if (!scannedPackages.has(depKey)) {
              nextLevel.push({
                name: depName,
                version: depVersion || 'latest',
                path: packagePath.includes(depName) ? packagePath : `${packagePath} → ${depName}`
              });
            }
          }
        }
      } catch (error) {
        if (options.verbose) {
          console.warn(`Warning: Could not get dependencies for ${packageName}: ${error.message}`);
        }
      }
    }
    
    currentLevel = nextLevel;
    depth++;
  }

  // Analyze the complete dependency tree for additional threats
  const treeThreats = analyzeDependencyTree(tree, options);
  threats.push(...treeThreats);

  return {
    threats,
    packagesScanned,
    tree
  };
}

/**
 * Scan a specific package for threats
 * @param {string} packageName - Package name
 * @param {string} version - Package version
 * @param {object} options - Scan options
 * @returns {Promise<Array>} Array of threats found
 */
async function scanPackage(packageName, version, options, packagePath = null) {
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
      performanceMetrics.errors++;
      if (options.verbose) {
        console.warn(`Warning: Could not fetch metadata for ${packageName}`);
      }
      return threats;
    }
    
    // Update performance metrics
    performanceMetrics.packagesScanned++;

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
    
    // Heuristic 9: Advanced AST analysis (disabled for performance)
    const astThreats = []; // Disabled tarball analysis
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
    
    // Heuristic 14: Signature verification and tampering detection
    const signatureThreats = await checkPackageSignatures(packageData, packageName, options);
    threats.push(...signatureThreats);
    
    // Cache the results
    setCachedResult(cacheKey, threats);
    
  } catch (error) {
    if (options.verbose) {
      console.warn(`Warning: Could not scan ${packageName}: ${error.message}`);
    }
  }
  
  // Add package path to threats if provided
  if (packagePath) {
    threats.forEach(threat => {
      // Try to find the actual file system path for the package
      const fs = require('fs');
      const path = require('path');
      
      // Check common locations for the package
      const possiblePaths = [
        path.join(process.cwd(), 'node_modules', packageName),
        path.join(process.cwd(), 'node_modules', packageName, 'package.json'),
        path.join('/usr/local/lib/node_modules', packageName),
        path.join('/usr/local/lib/node_modules', packageName, 'package.json'),
        path.join(process.env.HOME, '.npm', 'packages', packageName),
        path.join(process.env.HOME, '.npm', 'packages', packageName, 'package.json'),
        path.join(process.env.HOME, '.npm', '_cacache', 'content-v2', 'sha512'),
        path.join('/usr/local/share/.cache/npm', packageName),
        path.join(process.env.HOME, '.npm-global', 'lib', 'node_modules', packageName)
      ];
      
      let actualPath = null;
      for (const possiblePath of possiblePaths) {
        if (fs.existsSync(possiblePath)) {
          actualPath = possiblePath;
          break;
        }
      }
      
      threat.packagePath = actualPath || `/npm/registry/${packageName}`;
    });
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
    const timeout = 5000; // 5 second timeout
    
    performanceMetrics.networkRequests++;
    const request = https.get(url, { timeout }, (res) => {
      let data = '';
      
      // Handle different status codes
      if (res.statusCode === 404) {
        reject(new Error(`Package ${packageName} not found`));
        return;
      }
      
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode}: ${res.statusMessage}`));
        return;
      }
      
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        try {
          const packageData = JSON.parse(data);
          let versionData;
          
          if (version === 'latest') {
            versionData = packageData['dist-tags']?.latest;
            if (versionData) {
              versionData = packageData.versions[versionData];
            }
          } else {
            // Handle version ranges by finding the best match
            if (version.startsWith('^') || version.startsWith('~') || version.startsWith('>=')) {
              // For version ranges, try to find the latest compatible version
              const availableVersions = Object.keys(packageData.versions || {});
              if (availableVersions.length > 0) {
                // Sort versions and take the latest
                const sortedVersions = availableVersions.sort((a, b) => {
                  const aParts = a.split('.').map(Number);
                  const bParts = b.split('.').map(Number);
                  for (let i = 0; i < Math.max(aParts.length, bParts.length); i++) {
                    const aPart = aParts[i] || 0;
                    const bPart = bParts[i] || 0;
                    if (aPart !== bPart) return bPart - aPart;
                  }
                  return 0;
                });
                versionData = packageData.versions[sortedVersions[0]];
              }
            } else {
              versionData = packageData.versions?.[version];
            }
          }
          
          if (!versionData) {
            reject(new Error(`Version ${version} not found for package ${packageName}`));
            return;
          }
          
          resolve(versionData);
        } catch (error) {
          reject(new Error(`Failed to parse package data for ${packageName}: ${error.message}`));
        }
      });
      
      res.on('error', (error) => {
        reject(new Error(`Network error for ${packageName}: ${error.message}`));
      });
    });
    
    request.on('timeout', () => {
      request.destroy();
      reject(new Error(`Request timeout for ${packageName}`));
    });
    
    request.on('error', (error) => {
      reject(new Error(`Request error for ${packageName}: ${error.message}`));
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
    // Write buffer to temporary file first
    const tempTarballPath = path.join(tempDir, 'package.tgz');
    
    try {
      fs.writeFileSync(tempTarballPath, tarballBuffer);
      
      tar.extract({
        file: tempTarballPath,
        cwd: tempDir,
        strip: 1 // Remove the package-version/ prefix
      }, (err) => {
        // Clean up temporary tarball file
        try {
          fs.unlinkSync(tempTarballPath);
        } catch (cleanupErr) {
          // Ignore cleanup errors
        }
        
        if (err) {
          reject(new Error(`Failed to extract tarball: ${err.message}`));
        } else {
          resolve();
        }
      });
    } catch (writeErr) {
      reject(new Error(`Failed to write tarball: ${writeErr.message}`));
    }
  });
}

/**
 * Find all JavaScript files in a directory
 * @param {string} dirPath - Directory path
 * @returns {Promise<Array<string>>} Array of relative file paths
 */
async function findJavaScriptFiles(dirPath) {
  return new Promise((resolve, reject) => {
    glob.glob('**/*.{js,jsx,ts,tsx,mjs}', {
      cwd: dirPath,
      ignore: ['node_modules/**', '*.min.js', '*.bundle.js']
    }, (err, files) => {
      if (err) {
        reject(err);
      } else {
        resolve(files || []);
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
  
  // Skip analysis for package.json files to reduce false positives
  if (packageName.includes('package.json') || contentType === 'JSON') {
    return threats;
  }
  
  const entropy = calculateShannonEntropy(content);
  const threshold = ENTROPY_THRESHOLDS[contentType] || ENTROPY_THRESHOLDS.TEXT;
  
  // Only flag as suspicious if entropy is EXTREMELY high (indicating obfuscation)
  // Normal complex code has entropy 4.0-5.0, obfuscated code has entropy > 7.0
  if (entropy > 7.0) {
    threats.push({
      type: 'SUSPICIOUS_ENTROPY',
      message: `Suspicious high entropy detected (${entropy.toFixed(2)} > 7.0)`,
      package: packageName,
      severity: 'HIGH',
      details: `Content has suspiciously high entropy (${entropy.toFixed(2)}) - possible obfuscation or packed code`
    });
  }
  
  // Check for specific high-entropy patterns - but be much more conservative
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Only check very long lines (likely obfuscated)
    if (line.length > 200) {
      const lineEntropy = calculateShannonEntropy(line);
      // Much higher threshold for individual lines - only flag obvious obfuscation
      if (lineEntropy > 7.5) {
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
                  scriptContent.includes('bash -c "curl') ||
                  scriptContent.includes('bash -c "wget') ||
                  scriptContent.includes('bash -c "rm') ||
                  scriptContent.includes('node -e "http') ||
                  scriptContent.includes('chmod 777') ||
                  scriptContent.includes('curl -s http') ||
                  scriptContent.includes('wget -q http')) {
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

/**
 * Check package signatures and detect tampering
 * @param {object} packageData - Package metadata
 * @param {string} packageName - Package name
 * @param {object} options - Scan options
 * @returns {Promise<Array>} Array of signature-related threats
 */
async function checkPackageSignatures(packageData, packageName, options) {
  const threats = [];
  
  if (!packageData) {
    return threats;
  }
  
  try {
    // Check 1: Package integrity verification
    const integrityThreats = await checkPackageIntegrity(packageData, packageName);
    threats.push(...integrityThreats);
    
    // Check 2: Tarball signature verification
    const tarballThreats = await checkTarballSignatures(packageData, packageName, options);
    threats.push(...tarballThreats);
    
    // Check 3: Package.json signature validation
    const packageJsonThreats = await checkPackageJsonSignatures(packageData, packageName);
    threats.push(...packageJsonThreats);
    
    // Check 4: Maintainer signature verification
    const maintainerThreats = await checkMaintainerSignatures(packageData, packageName);
    threats.push(...maintainerThreats);
    
    // Check 5: GPG signature verification
    const gpgThreats = await checkGpgSignatures(packageData, packageName, options);
    threats.push(...gpgThreats);
    
  } catch (error) {
    if (options.verbose) {
      console.warn(`Warning: Could not verify signatures for ${packageName}: ${error.message}`);
    }
  }
  
  return threats;
}

/**
 * Check package integrity using checksums and hashes
 * @param {object} packageData - Package metadata
 * @param {string} packageName - Package name
 * @returns {Promise<Array>} Array of integrity threats
 */
async function checkPackageIntegrity(packageData, packageName) {
  const threats = [];
  
  try {
    // Check if package has integrity field (npm 5+)
    if (packageData.integrity) {
      // Verify the integrity hash format
      const integrityPattern = /^sha[0-9]+-[A-Za-z0-9+/=]+$/;
      if (!integrityPattern.test(packageData.integrity)) {
        threats.push({
          type: 'SUSPICIOUS_INTEGRITY',
          message: 'Package has malformed integrity hash',
          package: packageName,
          severity: 'HIGH',
          details: `Package "${packageName}" has suspicious integrity hash format: ${packageData.integrity}`
        });
      }
    }
    
    // Check for missing integrity (potential tampering)
    if (!packageData.integrity && packageData.version) {
      // Only flag if this is a recent package (npm 5+ should have integrity)
      const version = packageData.version;
      const majorVersion = parseInt(version.split('.')[0]);
      
      if (majorVersion >= 1) { // Most packages should have integrity
        threats.push({
          type: 'MISSING_INTEGRITY',
          message: 'Package missing integrity verification',
          package: packageName,
          severity: 'MEDIUM',
          details: `Package "${packageName}" is missing integrity hash, which could indicate tampering or old package format`
        });
      }
    }
    
    // Check for suspicious version jumps (potential account takeover)
    if (packageData.time && packageData.time[packageData.version]) {
      const versionTimes = Object.keys(packageData.time)
        .filter(v => v !== 'created' && v !== 'modified')
        .map(v => ({ version: v, time: new Date(packageData.time[v]) }))
        .sort((a, b) => a.time - b.time);
      
      // Look for suspiciously rapid version releases
      for (let i = 1; i < versionTimes.length; i++) {
        const timeDiff = versionTimes[i].time - versionTimes[i-1].time;
        const hoursDiff = timeDiff / (1000 * 60 * 60);
        
        if (hoursDiff < 1) { // Less than 1 hour between releases
          threats.push({
            type: 'SUSPICIOUS_VERSION_PATTERN',
            message: 'Suspicious rapid version releases detected',
            package: packageName,
            severity: 'HIGH',
            details: `Package "${packageName}" has versions released within ${hoursDiff.toFixed(1)} hours, which could indicate automated malicious releases`
          });
        }
      }
    }
    
  } catch (error) {
    // Skip integrity checks if there's an error
  }
  
  return threats;
}

/**
 * Check tarball signatures and detect tampering
 * @param {object} packageData - Package metadata
 * @param {string} packageName - Package name
 * @param {object} options - Scan options
 * @returns {Promise<Array>} Array of tarball signature threats
 */
async function checkTarballSignatures(packageData, packageName, options) {
  const threats = [];
  
  try {
    // Get tarball URL
    const tarballUrl = packageData.dist?.tarball;
    if (!tarballUrl) {
      return threats;
    }
    
    // Download tarball for analysis
    const tarballBuffer = await downloadTarball(tarballUrl);
    if (!tarballBuffer) {
      return threats;
    }
    
    // Check tarball size (suspiciously large or small)
    const tarballSize = tarballBuffer.length;
    const expectedSize = packageData.dist?.size;
    
    if (expectedSize && Math.abs(tarballSize - expectedSize) > 1024) { // 1KB difference
      threats.push({
        type: 'TARBALL_SIZE_MISMATCH',
        message: 'Tarball size mismatch detected',
        package: packageName,
        severity: 'HIGH',
        details: `Package "${packageName}" tarball size (${tarballSize}) doesn't match expected size (${expectedSize}), indicating possible tampering`
      });
    }
    
    // Check for suspiciously large tarballs (potential malware)
    if (tarballSize > 50 * 1024 * 1024) { // 50MB
      threats.push({
        type: 'SUSPICIOUSLY_LARGE_TARBALL',
        message: 'Suspiciously large tarball detected',
        package: packageName,
        severity: 'MEDIUM',
        details: `Package "${packageName}" tarball is ${(tarballSize / 1024 / 1024).toFixed(1)}MB, which is unusually large and could contain malicious content`
      });
    }
    
    // Calculate and verify checksums
    const crypto = require('crypto');
    const sha1Hash = crypto.createHash('sha1').update(tarballBuffer).digest('hex');
    const sha256Hash = crypto.createHash('sha256').update(tarballBuffer).digest('hex');
    
    // Check against npm registry hash if available
    if (packageData.dist?.shasum && packageData.dist.shasum !== sha1Hash) {
      threats.push({
        type: 'CHECKSUM_MISMATCH',
        message: 'Tarball checksum mismatch detected',
        package: packageName,
        severity: 'CRITICAL',
        details: `Package "${packageName}" tarball SHA1 checksum (${sha1Hash}) doesn't match registry checksum (${packageData.dist.shasum}), indicating tampering`
      });
    }
    
    // Store calculated hashes for future verification
    if (options.verbose) {
      console.log(`Package ${packageName} tarball verification:`);
      console.log(`  SHA1: ${sha1Hash}`);
      console.log(`  SHA256: ${sha256Hash}`);
      console.log(`  Size: ${tarballSize} bytes`);
    }
    
  } catch (error) {
    if (options.verbose) {
      console.warn(`Warning: Could not verify tarball signatures for ${packageName}: ${error.message}`);
    }
  }
  
  return threats;
}

/**
 * Check package.json signatures and detect tampering
 * @param {object} packageData - Package metadata
 * @param {string} packageName - Package name
 * @returns {Promise<Array>} Array of package.json signature threats
 */
async function checkPackageJsonSignatures(packageData, packageName) {
  const threats = [];
  
  try {
    // Check for suspicious package.json modifications
    const packageJsonString = JSON.stringify(packageData, null, 2);
    
    // Check for unexpected fields that could indicate tampering
    const suspiciousFields = [
      'eval(',
      'Function(',
      'require(',
      'import(',
      'exec(',
      'spawn(',
      'child_process'
    ];
    
    for (const field of suspiciousFields) {
      if (packageJsonString.includes(field)) {
        threats.push({
          type: 'SUSPICIOUS_PACKAGE_JSON_CONTENT',
          message: 'Suspicious content detected in package metadata',
          package: packageName,
          severity: 'HIGH',
          details: `Package "${packageName}" contains suspicious field "${field}" in package.json, which could indicate tampering`
        });
      }
    }
    
    // Check for missing essential fields
    const essentialFields = ['name', 'version', 'description'];
    for (const field of essentialFields) {
      if (!packageData[field]) {
        threats.push({
          type: 'MISSING_ESSENTIAL_FIELD',
          message: `Missing essential field: ${field}`,
          package: packageName,
          severity: 'MEDIUM',
          details: `Package "${packageName}" is missing essential field "${field}", which could indicate incomplete or tampered package`
        });
      }
    }
    
    // Check for suspicious version patterns
    if (packageData.version) {
      const version = packageData.version;
      
      // Check for suspicious version patterns
      if (version.includes('+') || version.includes('~') || version.includes('^')) {
        threats.push({
          type: 'SUSPICIOUS_VERSION_PATTERN',
          message: 'Suspicious version pattern detected',
          package: packageName,
          severity: 'LOW',
          details: `Package "${packageName}" has suspicious version pattern "${version}", which could indicate tampering`
        });
      }
      
      // Check for extremely high version numbers (potential automated releases)
      const versionParts = version.split('.');
      const majorVersion = parseInt(versionParts[0]);
      if (majorVersion > 100) {
        threats.push({
          type: 'SUSPICIOUS_VERSION_NUMBER',
          message: 'Suspiciously high version number detected',
          package: packageName,
          severity: 'MEDIUM',
          details: `Package "${packageName}" has suspiciously high major version number ${majorVersion}, which could indicate automated malicious releases`
        });
      }
    }
    
  } catch (error) {
    // Skip package.json signature checks if there's an error
  }
  
  return threats;
}

/**
 * Check maintainer signatures and detect account takeover
 * @param {object} packageData - Package metadata
 * @param {string} packageName - Package name
 * @returns {Promise<Array>} Array of maintainer signature threats
 */
async function checkMaintainerSignatures(packageData, packageName) {
  const threats = [];
  
  try {
    // Check maintainer information
    if (packageData.maintainers && Array.isArray(packageData.maintainers)) {
      for (const maintainer of packageData.maintainers) {
        // Check for suspicious maintainer patterns
        if (maintainer.email) {
          // Check for suspicious email patterns
          const suspiciousEmailPatterns = [
            /temp/i,
            /test/i,
            /fake/i,
            /spam/i,
            /throwaway/i,
            /disposable/i
          ];
          
          for (const pattern of suspiciousEmailPatterns) {
            if (pattern.test(maintainer.email)) {
              threats.push({
                type: 'SUSPICIOUS_MAINTAINER',
                message: 'Suspicious maintainer email detected',
                package: packageName,
                severity: 'HIGH',
                details: `Package "${packageName}" has maintainer with suspicious email "${maintainer.email}", which could indicate account takeover`
              });
            }
          }
          
          // Check for recently created email domains
          const emailDomain = maintainer.email.split('@')[1];
          if (emailDomain && emailDomain.includes('temp') || emailDomain.includes('throwaway')) {
            threats.push({
              type: 'SUSPICIOUS_MAINTAINER_DOMAIN',
              message: 'Suspicious maintainer email domain detected',
              package: packageName,
              severity: 'MEDIUM',
              details: `Package "${packageName}" has maintainer with suspicious email domain "${emailDomain}", which could indicate account takeover`
            });
          }
        }
        
        // Check for missing maintainer information
        if (!maintainer.email && !maintainer.name) {
          threats.push({
            type: 'INCOMPLETE_MAINTAINER_INFO',
            message: 'Incomplete maintainer information detected',
            package: packageName,
            severity: 'LOW',
            details: `Package "${packageName}" has maintainer with incomplete information, which could indicate account takeover`
          });
        }
      }
    }
    
    // Check for recent maintainer changes (potential account takeover)
    if (packageData.time && packageData.time.modified) {
      const modifiedTime = new Date(packageData.time.modified);
      const now = new Date();
      const daysSinceModified = (now - modifiedTime) / (1000 * 60 * 60 * 24);
      
      if (daysSinceModified < 7) { // Modified within last week
        threats.push({
          type: 'RECENT_MAINTAINER_CHANGE',
          message: 'Recent maintainer changes detected',
          package: packageName,
          severity: 'MEDIUM',
          details: `Package "${packageName}" was modified ${daysSinceModified.toFixed(1)} days ago, which could indicate recent account takeover`
        });
      }
    }
    
  } catch (error) {
    // Skip maintainer signature checks if there's an error
  }
  
  return threats;
}

/**
 * Check GPG signatures for package verification
 * @param {object} packageData - Package metadata
 * @param {string} packageName - Package name
 * @param {object} options - Scan options
 * @returns {Promise<Array>} Array of threats found
 */
async function checkGpgSignatures(packageData, packageName, options) {
  const threats = [];
  
  if (!packageData) {
    return threats;
  }
  
  try {
    let gpgSignatures = [];
    
    // Check for GPG signature in package metadata
    if (packageData.signatures) {
      // Check if package has GPG signatures
      gpgSignatures = packageData.signatures.filter(sig => 
        sig.type === 'gpg' || sig.type === 'pgp' || sig.keyid
      );
      
      if (gpgSignatures.length === 0) {
        threats.push({
          type: 'MISSING_GPG_SIGNATURE',
          message: 'Package missing GPG signature verification',
          package: packageName,
          severity: 'MEDIUM',
          details: `Package "${packageName}" does not have GPG signature verification, which could indicate tampering`
        });
      } else {
        // Verify GPG signatures
        for (const signature of gpgSignatures) {
          // Check signature validity
          if (!signature.valid) {
            threats.push({
              type: 'INVALID_GPG_SIGNATURE',
              message: 'Invalid GPG signature detected',
              package: packageName,
              severity: 'HIGH',
              details: `Package "${packageName}" has invalid GPG signature: ${signature.keyid || 'unknown'}`
            });
          }
          
          // Check for suspicious key patterns
          if (signature.keyid && signature.keyid.length < 8) {
            threats.push({
              type: 'SUSPICIOUS_GPG_KEY',
              message: 'Suspicious GPG key detected',
              package: packageName,
              severity: 'MEDIUM',
              details: `Package "${packageName}" uses suspiciously short GPG key: ${signature.keyid}`
            });
          }
        }
      }
    } else {
      // No signatures field at all
      threats.push({
        type: 'MISSING_GPG_SIGNATURE',
        message: 'Package missing GPG signature verification',
        package: packageName,
        severity: 'MEDIUM',
        details: `Package "${packageName}" does not have any signature verification, which could indicate tampering`
      });
    }
    
    // Check for GPG signature in package.json
    if (packageData._hasShrinkwrap === false && !packageData.signatures) {
      threats.push({
        type: 'MISSING_GPG_SIGNATURE',
        message: 'Package missing GPG signature in package.json',
        package: packageName,
        severity: 'LOW',
        details: `Package "${packageName}" package.json does not contain GPG signature information`
      });
    }
    
    // Check for GPG signature in tarball (only if no valid signatures exist)
    if (packageData.dist && packageData.dist.tarball && (!packageData.signatures || gpgSignatures.length === 0)) {
      try {
        const tarballUrl = packageData.dist.tarball;
        const signatureUrl = tarballUrl + '.asc'; // GPG signature file
        
        // Try to fetch GPG signature file
        const https = require('https');
        
        const signatureExists = await new Promise((resolve) => {
          const req = https.get(signatureUrl, (res) => {
            resolve(res.statusCode === 200);
          });
          req.on('error', () => resolve(false));
          req.setTimeout(5000, () => {
            req.destroy();
            resolve(false);
          });
        });
        
        if (!signatureExists) {
          threats.push({
            type: 'MISSING_GPG_SIGNATURE',
            message: 'Package tarball missing GPG signature file',
            package: packageName,
            severity: 'MEDIUM',
            details: `Package "${packageName}" tarball does not have accompanying GPG signature file (.asc)`
          });
        }
      } catch (error) {
        if (options.verbose) {
          console.warn(`Warning: Could not check GPG signature for ${packageName}: ${error.message}`);
        }
      }
    }
    
  } catch (error) {
    if (options.verbose) {
      console.warn(`Warning: Could not verify GPG signatures for ${packageName}: ${error.message}`);
    }
  }
  
  return threats;
}

module.exports = {
  scan,
  analyzeJavaScriptAST,
  checkObfuscatedIoCs,
  analyzePackageJson,
  detectDynamicRequires,
  checkPackageSignatures,
  checkPackageIntegrity,
  checkTarballSignatures,
  checkPackageJsonSignatures,
  checkMaintainerSignatures,
  checkGpgSignatures,
  analyzeContentEntropy,
  scanNodeModules,
  scanDirectory,
  buildAndScanDependencyTree,
  analyzeDependencyTree,
  detectCircularDependencies,
  calculateShannonEntropy
};
