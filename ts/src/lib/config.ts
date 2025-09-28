/**
 * Configuration Constants for NullVoid
 * Centralizes all configuration values and magic numbers
 */

import { ScanConfig, SecurityConfig, PerformanceConfig } from '../types';

/**
 * Cache configuration
 */
export const CACHE_CONFIG = {
  TTL: 5 * 60 * 1000, // 5 minutes
  MAX_SIZE: 1000, // Maximum number of cached items
  CLEANUP_INTERVAL: 60 * 1000 // 1 minute cleanup interval
} as const;

/**
 * Network configuration
 */
export const NETWORK_CONFIG = {
  TIMEOUT: 5000, // 5 seconds
  MAX_RETRIES: 3,
  RETRY_DELAY: 1000, // 1 second
  RATE_LIMIT: {
    MAX_REQUESTS: 100, // per minute
    WINDOW_SIZE: 60 * 1000 // 1 minute window
  }
} as const;

/**
 * Parallel processing configuration
 */
export const PARALLEL_CONFIG = {
  MAX_WORKERS: 8,
  CHUNK_SIZE: 10,
  TIMEOUT: 30000, // 30 seconds
  RETRY_ATTEMPTS: 2,
  MIN_CHUNK_SIZE: 5,
  MAX_CHUNK_SIZE: 20
} as const;

/**
 * File processing configuration
 */
export const FILE_CONFIG = {
  MAX_FILE_SIZE: 10 * 1024 * 1024, // 10MB
  MAX_FILES_PER_PACKAGE: 1000,
  SCAN_TIMEOUT: 30000 // 30 seconds per file
} as const;

/**
 * Entropy thresholds for different content types
 */
export const ENTROPY_THRESHOLDS = {
  JAVASCRIPT: 4.5,
  JSON: 3.0,
  TEXT: 2.5,
  BINARY: 6.0,
  DEFAULT: 4.0
} as const;

/**
 * Security patterns and configurations
 */
export const SECURITY_PATTERNS = {
  SUSPICIOUS_PATTERNS: [
    /eval\s*\(/gi,
    /Function\s*\(/gi,
    /setTimeout\s*\(\s*['"`]/gi,
    /setInterval\s*\(\s*['"`]/gi,
    /document\.write\s*\(/gi,
    /innerHTML\s*=/gi,
    /outerHTML\s*=/gi,
    /insertAdjacentHTML\s*\(/gi
  ],
  
  DANGEROUS_FUNCTIONS: [
    'eval',
    'Function',
    'setTimeout',
    'setInterval',
    'setImmediate',
    'process.nextTick',
    'require',
    'import',
    'exec',
    'spawn',
    'execFile'
  ],
  
  NETWORK_PATTERNS: [
    /fetch\s*\(/gi,
    /XMLHttpRequest/gi,
    /axios/gi,
    /request/gi,
    /http\./gi,
    /https\./gi,
    /net\./gi,
    /tls\./gi
  ],
  
  FILE_SYSTEM_PATTERNS: [
    /fs\./gi,
    /readFile/gi,
    /writeFile/gi,
    /unlink/gi,
    /mkdir/gi,
    /rmdir/gi,
    /chmod/gi,
    /chown/gi
  ]
} as const;

/**
 * Validation configuration
 */
export const VALIDATION_CONFIG = {
  PACKAGE_NAME_PATTERN: /^[a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]$/,
  PACKAGE_NAME_MAX_LENGTH: 214,
  PACKAGE_NAME_MIN_LENGTH: 1,
  VALID_FORMATS: ['json', 'table', 'yaml', 'sarif'],
  VALID_OUTPUT_FORMATS: ['json', 'table', 'yaml', 'sarif'],
  SEMVER_PATTERN: /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/,
  ALLOWED_EXTENSIONS: ['.js', '.mjs', '.ts', '.jsx', '.tsx', '.json'],
  
  SUSPICIOUS_PATTERNS: [
    /malware/gi,
    /virus/gi,
    /trojan/gi,
    /backdoor/gi,
    /keylogger/gi,
    /spyware/gi,
    /rootkit/gi,
    /botnet/gi
  ],
  
  VALID_PACKAGE_NAME: /^[a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]$/,
  VALID_LOCAL_PATH: /^[a-zA-Z0-9._/-]+$/,
  
  TRAVERSAL_PATTERNS: [
    /\.\.\//g,
    /\.\.\\/g,
    /\.\.%2f/gi,
    /\.\.%5c/gi,
    /\.\.%252f/gi,
    /\.\.%255c/gi
  ],
  
  DANGEROUS_PATTERNS: [
    /<script/gi,
    /javascript:/gi,
    /vbscript:/gi,
    /data:text\/html/gi,
    /onload\s*=/gi,
    /onerror\s*=/gi,
    /onclick\s*=/gi
  ],
  
  MALICIOUS_PATTERNS: [
    /eval\s*\(/gi,
    /Function\s*\(/gi,
    /document\.write/gi,
    /innerHTML\s*=/gi,
    /outerHTML\s*=/gi,
    /insertAdjacentHTML/gi,
    /setTimeout\s*\(\s*['"`]/gi,
    /setInterval\s*\(\s*['"`]/gi
  ],
  
  DANGEROUS_FILES: [
    'malware.js',
    'virus.js',
    'trojan.js',
    'backdoor.js',
    'keylogger.js',
    'spyware.js',
    'rootkit.js',
    'botnet.js'
  ],
  
  SUSPICIOUS_SCRIPTS: [
    'curl http',
    'wget http',
    'rm -rf',
    'chmod 777',
    'chown root',
    'sudo',
    'su -',
    'passwd',
    'useradd',
    'userdel'
  ]
} as const;

/**
 * Test patterns configuration
 */
export const TEST_PATTERNS_CONFIG = {
  JEST_OUTPUT_PATTERNS: {
    PASSED: /✓ (.+)/g,
    FAILED: /✗ (.+)/g,
    SKIPPED: /○ (.+)/g,
    TOTAL: /Tests:\s*(\d+)\s*(?:passed|failed|skipped)/g,
    SUMMARY: /Test Suites: (.+)\s*Tests: (.+)\s*Snapshots: (.+)\s*Time: (.+)/
  },
  
  BADGE_REGEX: /!\[([^\]]*)\]\(([^)]+)\)/g
} as const;

/**
 * Dependency confusion configuration
 */
export const DEPENDENCY_CONFUSION_CONFIG = {
  TIMELINE_THRESHOLDS: {
    SUSPICIOUS_AGE_DAYS: 7,
    RAPID_PUBLISHING_HOURS: 24,
    VERSION_GAP_DAYS: 30,
    CRITICAL: 1,
    HIGH_RISK: 3,
    SUSPICIOUS: 7
  },
  
  SIMILARITY_THRESHOLDS: {
    HIGH_SIMILARITY: 0.8,
    MEDIUM_SIMILARITY: 0.6,
    LOW_SIMILARITY: 0.4
  },
  
  SCOPE_PATTERNS: {
    PRIVATE_SCOPES: [
      /^@[a-z0-9-]+\/[a-z0-9._-]+$/,
      /^@[a-z0-9-]+$/
    ],
    PUBLIC_SCOPES: [
      /^[a-z0-9._-]+$/
    ]
  },
  
  SUSPICIOUS_NAME_PATTERNS: [
    /^[a-z0-9]{32,}$/, // Random-looking names
    /malware/i,
    /virus/i,
    /trojan/i,
    /backdoor/i,
    /keylogger/i,
    /spyware/i,
    /rootkit/i,
    /botnet/i
  ],
  
  REGISTRY_ENDPOINTS: {
    npm: 'https://registry.npmjs.org',
    yarn: 'https://registry.yarnpkg.com',
    github: 'https://npm.pkg.github.com'
  },
  
  ANALYSIS_SETTINGS: {
    MAX_GIT_COMMITS: 100,
    MAX_PACKAGE_VERSIONS: 50,
    TIMEOUT_MS: 10000,
    RETRY_ATTEMPTS: 3
  }
} as const;

/**
 * Popular frameworks and libraries
 */
export const POPULAR_FRAMEWORKS = [
  'react',
  'vue',
  'angular',
  'express',
  'koa',
  'fastify',
  'next',
  'nuxt',
  'gatsby',
  'webpack',
  'rollup',
  'vite',
  'parcel',
  'babel',
  'typescript',
  'eslint',
  'prettier',
  'jest',
  'mocha',
  'cypress',
  'playwright',
  'puppeteer'
] as const;

/**
 * Main configuration objects
 */
export const SCAN_CONFIG: ScanConfig = {
  maxFileSize: FILE_CONFIG.MAX_FILE_SIZE,
  maxTimeout: FILE_CONFIG.SCAN_TIMEOUT,
  enableSandbox: true,
  sandboxTimeout: 100,
  maxMemory: 128 * 1024 * 1024, // 128MB
  enableParallel: true,
  maxWorkers: PARALLEL_CONFIG.MAX_WORKERS
};

export const SECURITY_CONFIG: SecurityConfig = {
  allowedExtensions: [...VALIDATION_CONFIG.ALLOWED_EXTENSIONS],
  blockedPatterns: VALIDATION_CONFIG.SUSPICIOUS_PATTERNS.map(p => p.source),
  suspiciousPatterns: VALIDATION_CONFIG.SUSPICIOUS_PATTERNS.map(p => p.source),
  dangerousFunctions: [...SECURITY_PATTERNS.DANGEROUS_FUNCTIONS],
  networkPatterns: SECURITY_PATTERNS.NETWORK_PATTERNS.map(p => p.source),
  fileSystemPatterns: SECURITY_PATTERNS.FILE_SYSTEM_PATTERNS.map(p => p.source)
};

export const PERFORMANCE_CONFIG: PerformanceConfig = {
  cacheTtl: CACHE_CONFIG.TTL,
  maxCacheSize: CACHE_CONFIG.MAX_SIZE,
  rateLimit: {
    requests: NETWORK_CONFIG.RATE_LIMIT.MAX_REQUESTS,
    window: NETWORK_CONFIG.RATE_LIMIT.WINDOW_SIZE
  },
  timeouts: {
    network: NETWORK_CONFIG.TIMEOUT,
    file: FILE_CONFIG.SCAN_TIMEOUT,
    analysis: FILE_CONFIG.SCAN_TIMEOUT
  }
};

/**
 * Update configuration from environment variables
 */
export function updateConfigFromEnv(): void {
  // Update cache TTL from environment
  if (process.env['NULLVOID_CACHE_TTL']) {
    const ttl = parseInt(process.env['NULLVOID_CACHE_TTL'], 10);
    if (!isNaN(ttl) && ttl > 0) {
      (CACHE_CONFIG as any).TTL = ttl;
    }
  }
  
  // Update network timeout from environment
  if (process.env['NULLVOID_NETWORK_TIMEOUT']) {
    const timeout = parseInt(process.env['NULLVOID_NETWORK_TIMEOUT'], 10);
    if (!isNaN(timeout) && timeout > 0) {
      (NETWORK_CONFIG as any).TIMEOUT = timeout;
    }
  }
  
  // Update max workers from environment
  if (process.env['NULLVOID_MAX_WORKERS']) {
    const workers = parseInt(process.env['NULLVOID_MAX_WORKERS'], 10);
    if (!isNaN(workers) && workers > 0 && workers <= 32) {
      (PARALLEL_CONFIG as any).MAX_WORKERS = workers;
    }
  }
  
  // Update dependency confusion settings
  if (process.env['NULLVOID_DEP_CONFUSION_ENABLED']) {
    const enabled = process.env['NULLVOID_DEP_CONFUSION_ENABLED'].toLowerCase() === 'true';
    (DEPENDENCY_CONFUSION_CONFIG as any).ENABLED = enabled;
  }
}

// Detection configuration
export const DETECTION_CONFIG = {
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
    ]
  },
  OBFUSCATION_PATTERNS: {
    VARIABLE_MANGLING: /const\s+[a-z]\d+\s*=\s*[A-Z]/,
    MASSIVE_BLOB: /.{5000,}/,
    HEX_ARRAYS: /\[(0x[0-9a-fA-F]+,\s*){3,}/g,
    MODULE_APPEND: /module\.exports\s*=\s*[^;]+;\s*[^;]{1000,}/
  },
  IOC_PATTERNS: {
    URLS: /https?:\/\/[^\s'"]+/g,
    IPS: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g,
    DOMAINS: /\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b/g
  },
  DYNAMIC_REQUIRE_PATTERNS: {
    REQUIRE: /require\s*\(\s*['"`][^'"`]*['"`]\s*\)/g,
    IMPORT: /import\s*\(\s*['"`][^'"`]*['"`]\s*\)/g
  }
};

// Initialize configuration from environment
updateConfigFromEnv();
