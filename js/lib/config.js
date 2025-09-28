/**
 * Configuration Constants for NullVoid
 * Centralizes all configuration values and magic numbers
 */

/**
 * Cache configuration
 */
const CACHE_CONFIG = {
  TTL: 5 * 60 * 1000, // 5 minutes
  MAX_SIZE: 1000, // Maximum number of cached items
  CLEANUP_INTERVAL: 60 * 1000 // 1 minute cleanup interval
};

/**
 * Network configuration
 */
const NETWORK_CONFIG = {
  TIMEOUT: 5000, // 5 seconds
  MAX_RETRIES: 3,
  RETRY_DELAY: 1000, // 1 second
  RATE_LIMIT: {
    MAX_REQUESTS: 100, // per minute
    WINDOW_SIZE: 60 * 1000 // 1 minute window
  }
};

/**
 * Parallel processing configuration
 */
const PARALLEL_CONFIG = {
  MAX_WORKERS: 8,
  CHUNK_SIZE: 10,
  TIMEOUT: 30000, // 30 seconds
  RETRY_ATTEMPTS: 2,
  MIN_CHUNK_SIZE: 5,
  MAX_CHUNK_SIZE: 20
};

/**
 * File processing configuration
 */
const FILE_CONFIG = {
  MAX_FILE_SIZE: 10 * 1024 * 1024, // 10MB
  MAX_FILES_PER_PACKAGE: 1000,
  SCAN_TIMEOUT: 30000 // 30 seconds per file
};

/**
 * Entropy thresholds for different content types
 */
const ENTROPY_THRESHOLDS = {
  JAVASCRIPT: 5.0,
  JSON: 4.2,
  TEXT: 4.0,
  BINARY: 7.5,
  MINIMUM: 3.0,
  MAXIMUM: 8.0
};

/**
 * Package scanning configuration
 */
const SCAN_CONFIG = {
  MAX_DEPTH: 10,
  DEFAULT_DEPTH: 3,
  MAX_PACKAGES_PER_SCAN: 10000,
  TIMEOUT_PER_PACKAGE: 10000, // 10 seconds
  BATCH_SIZE: 50
};

/**
 * Security configuration
 */
const SECURITY_CONFIG = {
  MAX_SUSPICIOUS_PATTERNS: 100,
  MAX_THREATS_PER_PACKAGE: 50,
  SIGNATURE_TIMEOUT: 5000, // 5 seconds
  GPG_TIMEOUT: 10000 // 10 seconds
};

/**
 * Performance monitoring configuration
 */
const PERFORMANCE_CONFIG = {
  METRICS_INTERVAL: 1000, // 1 second
  MAX_METRICS_HISTORY: 100,
  SLOW_OPERATION_THRESHOLD: 5000 // 5 seconds
};

/**
 * Logging configuration
 */
const LOGGING_CONFIG = {
  DEFAULT_LEVEL: 'INFO',
  MAX_LOG_SIZE: 10 * 1024 * 1024, // 10MB
  MAX_LOG_FILES: 5,
  LOG_FORMAT: 'json'
};

/**
 * Registry configuration
 */
const REGISTRY_CONFIG = {
  NPM_REGISTRY_URL: 'https://registry.npmjs.org',
  TIMEOUT: 10000, // 10 seconds
  USER_AGENT: 'NullVoid-Security-Scanner/1.3.9',
  MAX_REDIRECTS: 5
};

/**
 * Threat detection configuration
 */
const THREAT_CONFIG = {
  SEVERITY_LEVELS: {
    CRITICAL: 0,
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3
  },
  DEFAULT_SEVERITY: 'MEDIUM',
  MAX_THREAT_DETAILS_LENGTH: 1000
};

/**
 * Malware detection configuration
 */
const DETECTION_CONFIG = {
  LEGITIMATE_PATTERNS: [
    /module\.exports\s*=\s*[^;]+;\s*/, // module.exports = ...;
    /exports\s*=\s*[^;]+;\s*/,         // exports = ...;
    /return\s+[^;]+;\s*/,              // return ...;
    /const\s+\w+\s*=\s*[^;]+;\s*/,     // const ... = ...;
    /let\s+\w+\s*=\s*[^;]+;\s*/,       // let ... = ...;
    /var\s+\w+\s*=\s*[^;]+;\s*/,       // var ... = ...;
    /module\.exports\s*=\s*\w+;?\s*/,   // module.exports = router; (with optional semicolon)
    /exports\s*=\s*\w+;?\s*/           // exports = router; (with optional semicolon)
  ],
  MALWARE_PATTERNS: {
    // Variable mangling patterns
    variableMangling: [
      /const\s+[a-z]\d+\s*=\s*[A-Z]/,  // const b3=I
      /var\s+[a-z]\d+\s*=\s*[A-Z]/,    // var b3=I
      /let\s+[a-z]\d+\s*=\s*[A-Z]/     // let b3=I
    ],
    
    // Obfuscation patterns
    obfuscation: [
      /\[(0x[0-9a-fA-F]+,\s*){3,}/,   // Hex arrays: [0x30,0xd0,0x59
      /\[('[A-Za-z0-9+/=]{8,}',\s*){5,}/, // Base64 arrays: ['dXNlcm5hbW'
      /String\.fromCharCode\s*\(/,     // String.fromCharCode obfuscation
      /atob\s*\(/,                     // Base64 decoding
      /btoa\s*\(/                      // Base64 encoding
    ],
    
    // Suspicious function patterns
    suspiciousFunctions: [
      /function\s+\w+\s*\(\s*\w+\s*,\s*\w+\s*\)\s*\{\s*const\s+\w+\s*=\s*\w+/, // Suspicious functions
      /eval\s*\(/,                    // eval calls
      /new\s+Function\s*\(/,           // Function constructor
      /setTimeout\s*\(\s*['"`]/,       // setTimeout with string
      /setInterval\s*\(\s*['"`]/       // setInterval with string
    ],
    
    // Dynamic module loading
    dynamicRequires: [
      /require\s*\(\s*['"`][^'"`]*['"`]\s*\)/, // Dynamic requires
      /import\s*\(\s*['"`][^'"`]*['"`]\s*\)/,  // Dynamic imports
      /__webpack_require__\s*\(/,       // Webpack requires
      /System\.import\s*\(/             // System.import
    ],
    
    // Wallet hijacking patterns
    walletHijacking: [
      /window\.ethereum\s*=\s*new\s+Proxy/,     // Ethereum proxy
      /Object\.defineProperty\s*\(\s*window\s*,\s*['"`]ethereum/, // Ethereum property override
      /window\.__defineGetter__\s*\(\s*['"`]ethereum/, // Ethereum getter override
      /eth_sendTransaction.*?params.*?to\s*[:=]/, // Transaction manipulation
      /eth_requestAccounts.*?params.*?from\s*[:=]/, // Account request manipulation
      /web3\.eth\.sendTransaction/,              // Web3 transaction sending
      /ethereum\.request.*?method.*?['"`]eth_sendTransaction['"`]/, // Ethereum RPC calls
      /wallet.*?address.*?replace/,             // Address replacement
      /private.*?key.*?extract/,                // Private key extraction
      /mnemonic.*?phrase.*?steal/,               // Mnemonic phrase theft
      /seed.*?phrase.*?extract/                 // Seed phrase extraction
    ],
    
    // Network manipulation patterns
    networkManipulation: [
      /fetch\s*\(\s*['"`]https?:\/\/[^'"`]*['"`]/, // Suspicious fetch calls
      /XMLHttpRequest.*?open.*?POST/,            // XHR POST requests
      /axios\.post.*?https?:\/\//,               // Axios POST requests
      /request.*?post.*?https?:\/\//,            // Request POST calls
      /http.*?post.*?https?:\/\//,               // HTTP POST requests
      /websocket.*?connect.*?wss?:\/\//,         // WebSocket connections
      /socket\.io.*?connect/,                    // Socket.io connections
      /tcp.*?connect.*?remote/,                  // TCP connections
      /udp.*?send.*?packet/                      // UDP packet sending
    ],
    
    // File system manipulation patterns
    fileSystemManipulation: [
      /fs\.writeFile.*?sensitive/,              // Writing sensitive files
      /fs\.readFile.*?password/,                 // Reading password files
      /fs\.unlink.*?log/,                       // Deleting log files
      /fs\.mkdir.*?hidden/,                     // Creating hidden directories
      /fs\.chmod.*?777/,                        // Setting dangerous permissions
      /fs\.copyFile.*?config/,                  // Copying config files
      /fs\.rename.*?backup/,                    // Renaming backup files
      /fs\.stat.*?system/,                      // Checking system files
      /fs\.access.*?root/,                      // Accessing root files
      /fs\.exists.*?admin/                      // Checking admin files
    ],
    
    // Crypto and encryption patterns
    cryptoManipulation: [
      /crypto\.createHash.*?md5/,               // MD5 hashing (weak)
      /crypto\.createHash.*?sha1/,              // SHA1 hashing (weak)
      /crypto\.randomBytes.*?32/,               // Random byte generation
      /crypto\.createCipher.*?aes/,             // AES encryption
      /crypto\.createDecipher.*?aes/,           // AES decryption
      /crypto\.createSign.*?rsa/,               // RSA signing
      /crypto\.createVerify.*?rsa/,             // RSA verification
      /crypto\.createHmac.*?sha256/,            // HMAC SHA256
      /crypto\.pbkdf2.*?password/,              // Password-based key derivation
      /crypto\.scrypt.*?salt/                   // Scrypt key derivation
    ],
    
    // Anti-analysis and evasion patterns
    antiAnalysis: [
      /debugger\s*;/,                           // Debugger statements
      /console\.log.*?debug/,                   // Debug logging
      /console\.trace.*?stack/,                 // Stack tracing
      /console\.time.*?performance/,            // Performance timing
      /console\.profile.*?cpu/,                 // CPU profiling
      /console\.count.*?execution/,             // Execution counting
      /console\.assert.*?condition/,            // Assertion checking
      /console\.warn.*?deprecated/,             // Deprecation warnings
      /console\.error.*?exception/,             // Exception logging
      /console\.info.*?information/             // Information logging
    ],
    
    // Data exfiltration patterns
    dataExfiltration: [
      /exfiltrate/,                             // Data exfiltration
      /keylogger/,                              // Keylogger
      /steal/,                                  // Data theft
      /extract/,                                // Data extraction
      /harvest/,                                // Data harvesting
      /collect/,                                // Data collection
      /gather/,                                 // Data gathering
      /capture/,                                // Data capture
      /sniff/,                                  // Data sniffing
      /intercept/                               // Data interception
    ]
  }
};

/**
 * Test result parsing patterns for badge generation
 */
const TEST_PATTERNS_CONFIG = {
  JEST_PATTERNS: [
    /Tests:\s*(\d+)\s+passed,\s*(\d+)\s+total/,
    /Tests:\s*(\d+)\s+passed/,
    /(\d+)\s+passed,\s*(\d+)\s+total/,
    /(\d+)\s+passing,\s*(\d+)\s+total/,
    /(\d+)\s+passing/
  ],
  BADGE_REGEX: /\[!\[Tests\]\([^)]+\)\]/g
};

/**
 * Validation configuration
 */
const VALIDATION_CONFIG = {
  // Package name validation patterns
  VALID_PACKAGE_NAME: /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/i,
  VALID_LOCAL_PATH: /^[./]|^[a-zA-Z0-9._-]+\/[a-zA-Z0-9._-]+/,
  
  // Suspicious patterns for security validation
  SUSPICIOUS_PATTERNS: [
    /malware/i,
    /virus/i,
    /trojan/i,
    /backdoor/i,
    /hack/i,
    /crack/i,
    /keygen/i,
    /[a-z0-9]{32,}/, // Random-looking names
    /^[0-9]+$/ // Only numbers
  ],
  
  // Path traversal patterns
  TRAVERSAL_PATTERNS: [
    /\.\./, // Path traversal
    /\/\//, // Double slashes
    /\\\\/, // Double backslashes
    /[<>:"|?*]/, // Invalid characters
    /^\./, // Hidden files (unless explicitly allowed)
    /node_modules\/\.\./, // Escaping node_modules
    /\.git/, // Git directories
    /\.env/, // Environment files
    /package-lock\.json/, // Lock files
    /yarn\.lock/ // Yarn lock files
  ],
  
  // Dangerous command patterns
  DANGEROUS_PATTERNS: [
    /[;&|`$(){}[\]<>]/,
    /rm\s+-rf/,
    /curl\s+/,
    /wget\s+/,
    /eval\s*\(/,
    /exec\s*\(/,
    /spawn\s*\(/,
    /system\s*\(/
  ],
  
  // Malicious code patterns
  MALICIOUS_PATTERNS: [
    // Direct code execution
    /eval\s*\(/gi,
    /new\s+Function\s*\(/gi,
    /setTimeout\s*\(\s*['"`][^'"`]*['"`]/gi,
    /setInterval\s*\(\s*['"`][^'"`]*['"`]/gi,
    
    // System access
    /require\s*\(\s*['"`](?:fs|child_process|os|path)['"`]/gi,
    /import\s*['"`](?:fs|child_process|os|path)['"`]/gi,
    
    // Network access
    /fetch\s*\(/gi,
    /XMLHttpRequest/gi,
    /http\.(?:get|post|request)/gi,
    
    // Process manipulation
    /process\s*\.(?:exit|kill|spawn)/gi,
    /child_process\s*\.(?:exec|spawn|fork)/gi
  ],
  
  // Dangerous files to skip
  DANGEROUS_FILES: [
    'package-lock.json',
    'yarn.lock',
    '.env',
    '.env.local',
    '.env.production',
    '.env.development',
    '.env.test',
    '.git',
    '.gitignore',
    '.DS_Store',
    'Thumbs.db'
  ],
  
  // Valid output formats
  VALID_OUTPUT_FORMATS: ['json', 'table', 'yaml', 'sarif'],
  
  // Allowed file extensions
  ALLOWED_EXTENSIONS: ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.json', '.yml', '.yaml'],
  
  // Semver pattern for version validation
  SEMVER_PATTERN: /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/,
  
  // Package name validation
  PACKAGE_NAME_PATTERN: /^[a-zA-Z0-9._-]+$/,
  PACKAGE_NAME_MAX_LENGTH: 214,
  PACKAGE_NAME_MIN_LENGTH: 1,
  
  // Popular frameworks for dependency analysis
  POPULAR_FRAMEWORKS: ['express', 'react', 'vue', 'angular', 'next', 'nuxt', 'svelte', 'webpack', 'babel', 'typescript', 'lodash', 'moment', 'axios', 'jquery'],
  
  // Suspicious scripts patterns
  SUSPICIOUS_SCRIPTS: ['curl', 'wget', 'eval', 'require', 'child_process', 'fs.writeFile', 'fs.unlink', 'process.exit', 'exec', 'spawn', 'fork', 'download', 'fetch']
};

/**
 * Get configuration value with fallback
 * @param {object} config - Configuration object
 * @param {string} key - Configuration key
 * @param {*} defaultValue - Default value if key not found
 * @returns {*} Configuration value
 */
function getConfigValue(config, key, defaultValue = null) {
  const keys = key.split('.');
  let current = config;
  
  for (const k of keys) {
    if (current && typeof current === 'object' && k in current) {
      current = current[k];
    } else {
      return defaultValue;
    }
  }
  
  return current;
}

/**
 * Update configuration from environment variables
 * @param {object} config - Configuration object to update
 * @param {object} envMappings - Environment variable mappings
 */
function updateConfigFromEnv(config, envMappings) {
  for (const [envKey, configPath] of Object.entries(envMappings)) {
    const envValue = process.env[envKey];
    if (envValue !== undefined) {
      const keys = configPath.split('.');
      let current = config;
      
      for (let i = 0; i < keys.length - 1; i++) {
        if (!current[keys[i]]) {
          current[keys[i]] = {};
        }
        current = current[keys[i]];
      }
      
      // Convert string values to appropriate types
      let value = envValue;
      if (envValue === 'true') value = true;
      else if (envValue === 'false') value = false;
      else if (!isNaN(envValue) && !isNaN(parseFloat(envValue))) value = parseFloat(envValue);
      
      current[keys[keys.length - 1]] = value;
    }
  }
}

// Environment variable mappings
const ENV_MAPPINGS = {
  NULLVOID_CACHE_TTL: 'CACHE_CONFIG.TTL',
  NULLVOID_CACHE_MAX_SIZE: 'CACHE_CONFIG.MAX_SIZE',
  NULLVOID_NETWORK_TIMEOUT: 'NETWORK_CONFIG.TIMEOUT',
  NULLVOID_MAX_WORKERS: 'PARALLEL_CONFIG.MAX_WORKERS',
  NULLVOID_CHUNK_SIZE: 'PARALLEL_CONFIG.CHUNK_SIZE',
  NULLVOID_MAX_FILE_SIZE: 'FILE_CONFIG.MAX_FILE_SIZE',
  NULLVOID_MAX_DEPTH: 'SCAN_CONFIG.MAX_DEPTH',
  NULLVOID_LOG_LEVEL: 'LOGGING_CONFIG.DEFAULT_LEVEL'
};

// Dependency Confusion Detection Configuration
const DEPENDENCY_CONFUSION_CONFIG = {
  // Timeline thresholds (in days)
  TIMELINE_THRESHOLDS: {
    SUSPICIOUS: 30,      // Package created < 30 days before first git usage
    HIGH_RISK: 7,        // Package created < 7 days before first git usage
    CRITICAL: 1          // Package created < 1 day before first git usage
  },
  
  // Similarity thresholds
  SIMILARITY_THRESHOLDS: {
    SUSPICIOUS: 0.8,     // 80% similarity
    HIGH_RISK: 0.9,      // 90% similarity
    CRITICAL: 0.95       // 95% similarity
  },
  
  // Scope patterns
  SCOPE_PATTERNS: {
    PRIVATE_SCOPES: [
      '@company', '@internal', '@private', '@local',
      '@dev', '@test', '@staging', '@prod'
    ],
    PUBLIC_SCOPES: [
      '@types', '@babel', '@webpack', '@rollup',
      '@angular', '@vue', '@react', '@next'
    ]
  },
  
  // Suspicious package name patterns
  SUSPICIOUS_NAME_PATTERNS: [
    /^[a-z]+-[a-z]+-[a-z]+$/,  // kebab-case with 3+ parts
    /^[a-z]+\d+[a-z]+$/,       // mixed alphanumeric
    /^[a-z]{1,3}[0-9]{2,4}$/,  // short letters + numbers
    /^[a-z]+-[0-9]+$/,         // letters-dash-numbers
    /^[0-9]+[a-z]+$/,          // numbers-letters
    /^[a-z]+[0-9]+[a-z]+$/     // letters-numbers-letters
  ],
  
  // Registry endpoints
  REGISTRY_ENDPOINTS: {
    npm: 'https://registry.npmjs.org',
    github: 'https://npm.pkg.github.com'
  },
  
  // Analysis settings
  ANALYSIS_SETTINGS: {
    ENABLED: true,
    TIMEOUT: 10000,        // 10 seconds timeout for registry requests
    MAX_PACKAGES: 100,     // Maximum packages to analyze per scan
    CACHE_TTL: 3600000     // 1 hour cache for registry data
  }
};

// Update configurations from environment
updateConfigFromEnv({
  CACHE_CONFIG,
  NETWORK_CONFIG,
  PARALLEL_CONFIG,
  FILE_CONFIG,
  SCAN_CONFIG,
  LOGGING_CONFIG,
  DEPENDENCY_CONFUSION_CONFIG
}, ENV_MAPPINGS);

module.exports = {
  CACHE_CONFIG,
  NETWORK_CONFIG,
  PARALLEL_CONFIG,
  FILE_CONFIG,
  ENTROPY_THRESHOLDS,
  SCAN_CONFIG,
  SECURITY_CONFIG,
  PERFORMANCE_CONFIG,
  LOGGING_CONFIG,
  REGISTRY_CONFIG,
  THREAT_CONFIG,
  DETECTION_CONFIG,
  TEST_PATTERNS_CONFIG,
  VALIDATION_CONFIG,
  DEPENDENCY_CONFUSION_CONFIG,
  getConfigValue,
  updateConfigFromEnv,
  ENV_MAPPINGS
};
