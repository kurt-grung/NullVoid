/**
 * Secure Sandbox for Malicious Code Analysis
 * Implements VM-based isolation for safe code analysis
 */

const vm = require('vm');
const path = require('path');
const fs = require('fs');
const { isNullVoidCode, isTestFile } = require('./nullvoidDetection');

/**
 * Security configuration for sandbox
 */
const SANDBOX_CONFIG = {
  timeout: 100, // 100ms timeout for code execution
  maxMemory: 128 * 1024 * 1024, // 128MB memory limit
  maxExecutionTime: 1000, // 1 second max execution time
  allowCodeGeneration: false,
  allowCodeGenerationFromStrings: false
};

/**
 * Create a secure sandbox context for code analysis
 * @returns {vm.Context} Isolated VM context
 */
function createSecureSandbox() {
  const sandbox = {
    // Mock console to prevent output manipulation
    console: {
      log: () => {},
      error: () => {},
      warn: () => {},
      info: () => {},
      debug: () => {}
    },
    
    // Mock process to prevent system access
    process: {
      exit: () => {},
      env: {},
      platform: 'sandbox',
      version: 'sandbox',
      versions: { node: 'sandbox' },
      cwd: () => '/sandbox',
      chdir: () => {},
      nextTick: () => {},
      setImmediate: () => {},
      setTimeout: () => {},
      clearTimeout: () => {},
      setInterval: () => {},
      clearInterval: () => {}
    },
    
    // Block require to prevent module loading
    require: () => {
      throw new Error('require() is not allowed in sandbox');
    },
    
    // Block import to prevent ES module loading
    import: () => {
      throw new Error('import() is not allowed in sandbox');
    },
    
    // Mock global objects
    global: {},
    globalThis: {},
    
    // Mock common globals
    Buffer: undefined,
    __dirname: '/sandbox',
    __filename: '/sandbox/analysis.js',
    
    // Block dangerous functions
    eval: () => {
      throw new Error('eval() is not allowed in sandbox');
    },
    
    Function: () => {
      throw new Error('Function() constructor is not allowed in sandbox');
    },
    
    // Block file system access
    fs: undefined,
    
    // Block child process access
    child_process: undefined,
    
    // Block network access
    http: undefined,
    https: undefined,
    net: undefined,
    tls: undefined,
    
    // Block crypto access (except for analysis)
    crypto: {
      // Only allow safe crypto functions for analysis
      createHash: () => ({
        update: () => ({ digest: () => 'sandbox-hash' })
      })
    },
    
    // Mock other dangerous modules
    os: undefined,
    path: undefined,
    url: undefined,
    querystring: undefined,
    util: undefined
  };
  
  return vm.createContext(sandbox, {
    codeGeneration: SANDBOX_CONFIG.allowCodeGeneration ? {} : { strings: false, wasm: false },
    microtaskMode: 'afterEvaluate'
  });
}

/**
 * Safely analyze malicious code in sandbox
 * @param {string} code - Code to analyze
 * @param {string} filename - Filename for context
 * @returns {object} Analysis result with threats and safety status
 */
function analyzeCodeInSandbox(code, filename = 'analysis.js') {
  const { isNullVoidCode } = require('./nullvoidDetection');
  
  // Skip analysis for NullVoid's own code
  if (isNullVoidCode(filename)) {
    return {
      threats: [],
      safe: true,
      executionTime: 0,
      executionError: null
    };
  }
  
  const context = createSecureSandbox();
  const threats = [];
  let executionResult = null;
  let executionError = null;
  let executionTime = 0;
  
  try {
    // Create script with timeout
    const script = new vm.Script(code, {
      filename: filename,
      timeout: SANDBOX_CONFIG.timeout,
      displayErrors: false,
      produceCachedData: false
    });
    
    const startTime = Date.now();
    
    // Run in sandbox with additional timeout
    executionResult = script.runInContext(context, {
      timeout: SANDBOX_CONFIG.timeout,
      breakOnSigint: true,
      displayErrors: false
    });
    
    executionTime = Date.now() - startTime;
    
    // Check for suspicious execution patterns
    if (executionTime > SANDBOX_CONFIG.timeout) {
      threats.push({
        type: 'TIMEOUT_EXCEEDED',
        severity: 'HIGH',
        message: 'Code execution exceeded timeout limit',
        details: `Execution took ${executionTime}ms, limit is ${SANDBOX_CONFIG.timeout}ms`
      });
    }
    
  } catch (error) {
    executionError = error;
    
    // Analyze error types for threat detection
    if (error.message.includes('require')) {
      threats.push({
        type: 'MODULE_LOADING_ATTEMPT',
        severity: 'HIGH',
        message: 'Code attempted to load modules',
        details: 'Malicious code tried to use require() or import()'
      });
    }
    
    if (error.message.includes('eval') || error.message.includes('Function')) {
      threats.push({
        type: 'CODE_GENERATION_ATTEMPT',
        severity: 'CRITICAL',
        message: 'Code attempted dynamic code generation',
        details: 'Malicious code tried to use eval() or Function() constructor'
      });
    }
    
    if (error.message.includes('timeout') || error.code === 'ERR_SCRIPT_EXECUTION_TIMEOUT') {
      threats.push({
        type: 'EXECUTION_TIMEOUT',
        severity: 'HIGH',
        message: 'Code execution timed out',
        details: 'Code may contain infinite loops or blocking operations'
      });
    }
    
    if (error.message.includes('memory')) {
      threats.push({
        type: 'MEMORY_EXHAUSTION',
        severity: 'HIGH',
        message: 'Code attempted memory exhaustion',
        details: 'Code may contain memory-intensive operations'
      });
    }
  }
  
  return {
    threats,
    executionResult,
    executionError,
    executionTime,
    safe: threats.length === 0 // Only consider unsafe if threats are detected
  };
}

/**
 * Analyze code for wallet hijacking patterns safely
 * @param {string} code - Code to analyze
 * @param {string} filename - Filename for context
 * @returns {Array} Array of detected wallet threats
 */
function analyzeWalletThreats(code, filename = 'analysis.js') {
  const threats = [];
  
  // Check if this is NullVoid's own code - if so, return empty threats
  
  // If this is NullVoid's own code, return empty threats
  if (isNullVoidCode(filename)) {
    return threats;
  }
  
  // Advanced wallet hijacking patterns
  const walletPatterns = {
    // Direct wallet hijacking
    ethereumHijack: [
      /window\s*\.\s*ethereum\s*=\s*new\s+Proxy/gi,
      /Object\.defineProperty\s*\(\s*window\s*,\s*['"`]ethereum/gi,
      /window\.__defineGetter__\s*\(\s*['"`]ethereum/gi,
      /window\.ethereum\s*=\s*.*?proxy/gi
    ],
    
    // Transaction manipulation
    transactionRedirect: [
      /eth_sendTransaction.*?params.*?to\s*[:=]/gi,
      /params\[0\]\.to\s*=\s*['"`]0x[a-fA-F0-9]{40}/gi,
      /transaction\.to\s*=.*?attacker/gi,
      /sendTransaction.*?replace.*?address/gi
    ],
    
    // Address replacement
    addressSwap: [
      /replace\s*\(\s*\/0x[a-fA-F0-9]{40}\/.*?,\s*['"`]0x/gi,
      /0x[a-fA-F0-9]{40}.*?\/\/.*?(attacker|wallet|address)/gi,
      /\.replace\s*\(\s*['"`]0x[a-fA-F0-9]{40}/gi
    ],
    
    // Multi-chain targeting
    multiChain: [
      /bitcoin.*?address.*?replace/gi,
      /litecoin.*?L[a-km-zA-HJ-NP-Z1-9]{26,33}/gi,
      /tron.*?T[a-km-zA-HJ-NP-Z1-9]{33}/gi,
      /solana.*?[1-9A-HJ-NP-Za-km-z]{32,44}/gi,
      /polygon.*?0x[a-fA-F0-9]{40}/gi,
      /bsc.*?0x[a-fA-F0-9]{40}/gi
    ],
    
    // Obfuscation detection
    obfuscation: [
      /eval\s*\(\s*String\.fromCharCode/gi,
      /Function\s*\(\s*['"`]return/gi,
      /_0x[a-f0-9]{4,6}\s*\(/gi,
      /\[\s*['"`]\\x[0-9a-f]{2}/gi,
      /atob\s*\(\s*['"`][A-Za-z0-9+/=]+['"`]/gi
    ],
    
    // Network interception
    networkHooks: [
      /XMLHttpRequest\.prototype\.open\s*=/gi,
      /fetch\s*=\s*.*?function/gi,
      /Response\.prototype\.json\s*=/gi,
      /axios\.interceptors/gi
    ]
  };
  
  // Check each pattern category
  for (const [threatType, patterns] of Object.entries(walletPatterns)) {
    for (const pattern of patterns) {
      if (pattern.test(code)) {
        threats.push({
          type: `WALLET_${threatType.toUpperCase()}`,
          severity: calculateSeverity(threatType),
          message: `Detected ${threatType} pattern`,
          details: `Pattern matched: ${pattern.toString()}`,
          confidence: calculateConfidence(code, pattern),
          filename: filename
        });
      }
    }
  }
  
  // Advanced heuristics
  if (hasHighEntropy(code) && hasWalletKeywords(code)) {
    threats.push({
      type: 'OBFUSCATED_WALLET_CODE',
      severity: 'HIGH',
      message: 'Detected obfuscated wallet manipulation code',
      details: 'High entropy code contains wallet-related keywords',
      confidence: 0.85,
      filename: filename
    });
  }
  
  return threats;
}

/**
 * Calculate threat severity based on pattern type
 * @param {string} threatType - Type of threat detected
 * @returns {string} Severity level
 */
function calculateSeverity(threatType) {
  const severityMap = {
    'ethereumHijack': 'CRITICAL',
    'transactionRedirect': 'CRITICAL',
    'addressSwap': 'HIGH',
    'multiChain': 'HIGH',
    'obfuscation': 'MEDIUM',
    'networkHooks': 'HIGH'
  };
  
  return severityMap[threatType] || 'MEDIUM';
}

/**
 * Calculate confidence score for threat detection
 * @param {string} code - Code being analyzed
 * @param {RegExp} pattern - Pattern that matched
 * @returns {number} Confidence score (0-1)
 */
function calculateConfidence(code, pattern) {
  const matches = code.match(pattern);
  if (!matches) return 0;
  
  // Higher confidence for multiple matches
  const matchCount = matches.length;
  const baseConfidence = 0.7;
  
  return Math.min(0.95, baseConfidence + (matchCount * 0.1));
}

/**
 * Check if code has high entropy (indicating obfuscation)
 * @param {string} code - Code to analyze
 * @returns {boolean} True if high entropy detected
 */
function hasHighEntropy(code) {
  // Simple entropy calculation
  const lines = code.split('\n');
  let highEntropyLines = 0;
  
  for (const line of lines) {
    if (line.length > 100) {
      // Check for random-looking character sequences
      const randomPattern = /[a-zA-Z0-9]{20,}/g;
      const matches = line.match(randomPattern);
      
      if (matches && matches.length > 2) {
        highEntropyLines++;
      }
    }
  }
  
  return highEntropyLines > lines.length * 0.3;
}

/**
 * Check if code contains wallet-related keywords
 * @param {string} code - Code to analyze
 * @returns {boolean} True if wallet keywords found
 */
function hasWalletKeywords(code) {
  const walletKeywords = [
    'ethereum', 'bitcoin', 'wallet', 'crypto', 'blockchain',
    'metamask', 'web3', 'transaction', 'address', 'private',
    'key', 'seed', 'mnemonic', 'hdwallet', 'trezor', 'ledger'
  ];
  
  const lowerCode = code.toLowerCase();
  return walletKeywords.some(keyword => lowerCode.includes(keyword));
}

/**
 * Safe file analysis with sandbox protection
 * @param {string} filePath - Path to file to analyze
 * @returns {object} Analysis result
 */
function analyzeFileSafely(filePath) {
  try {
    // Validate file path first
    const normalizedPath = path.normalize(filePath);
    const absolutePath = path.resolve(normalizedPath);
    
    // Check if file exists and is readable
    if (!fs.existsSync(absolutePath)) {
      throw new Error(`File does not exist: ${absolutePath}`);
    }
    
    const stats = fs.statSync(absolutePath);
    if (!stats.isFile()) {
      throw new Error(`Path is not a file: ${absolutePath}`);
    }
    
    // Check if this is NullVoid's own code - if so, return safe analysis
    const fileName = path.basename(filePath);
    
    // If this is NullVoid's own code, return safe analysis
    if (isNullVoidCode(absolutePath)) {
      return {
        filePath: absolutePath,
        threats: [],
        safe: true,
        executionTime: 0,
        error: null
      };
    }
    
    // Read file content
    const content = fs.readFileSync(absolutePath, 'utf8');
    
    // Analyze in sandbox
    const sandboxResult = analyzeCodeInSandbox(content, path.basename(filePath));
    
    // Additional static analysis
    const walletThreats = analyzeWalletThreats(content, path.basename(filePath));
    
    return {
      filePath: absolutePath,
      threats: [...sandboxResult.threats, ...walletThreats],
      safe: sandboxResult.safe,
      executionTime: sandboxResult.executionTime,
      error: sandboxResult.executionError
    };
    
  } catch (error) {
    return {
      filePath: filePath,
      threats: [{
        type: 'ANALYSIS_ERROR',
        severity: 'MEDIUM',
        message: 'Failed to analyze file safely',
        details: error.message
      }],
      safe: false,
      error: error
    };
  }
}

module.exports = {
  createSecureSandbox,
  analyzeCodeInSandbox,
  analyzeWalletThreats,
  analyzeFileSafely,
  SANDBOX_CONFIG
};
