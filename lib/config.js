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
  ALLOWED_EXTENSIONS: ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.json', '.yml', '.yaml'],
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

// Update configurations from environment
updateConfigFromEnv({
  CACHE_CONFIG,
  NETWORK_CONFIG,
  PARALLEL_CONFIG,
  FILE_CONFIG,
  SCAN_CONFIG,
  LOGGING_CONFIG
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
  getConfigValue,
  updateConfigFromEnv,
  ENV_MAPPINGS
};
