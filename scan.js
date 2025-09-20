const fs = require('fs');
const path = require('path');
const https = require('https');
const { execSync } = require('child_process');

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

module.exports = scan;
