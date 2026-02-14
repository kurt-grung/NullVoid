#!/usr/bin/env node
/**
 * Validate NullVoid configuration (js/lib/config.js).
 * Run from repo root: node scripts/validate-config.js
 * Exits 0 if valid, 1 with messages if invalid.
 */

const path = require('path');

const configPath = path.resolve(__dirname, '..', 'js', 'lib', 'config.js');
let config;
try {
  config = require(configPath);
} catch (e) {
  console.error('validate-config: failed to load config:', e.message);
  process.exit(1);
}

const { DEPENDENCY_CONFUSION_CONFIG, CACHE_CONFIG, VALIDATION_CONFIG } = config;
const errors = [];

if (!DEPENDENCY_CONFUSION_CONFIG) {
  errors.push('DEPENDENCY_CONFUSION_CONFIG is missing');
} else {
  if (!DEPENDENCY_CONFUSION_CONFIG.TIMELINE_THRESHOLDS || typeof DEPENDENCY_CONFUSION_CONFIG.TIMELINE_THRESHOLDS.SUSPICIOUS !== 'number') {
    errors.push('DEPENDENCY_CONFUSION_CONFIG.TIMELINE_THRESHOLDS must define SUSPICIOUS (number)');
  }
  if (!DEPENDENCY_CONFUSION_CONFIG.REGISTRY_ENDPOINTS || !DEPENDENCY_CONFUSION_CONFIG.REGISTRY_ENDPOINTS.npm) {
    errors.push('DEPENDENCY_CONFUSION_CONFIG.REGISTRY_ENDPOINTS must define npm');
  }
  if (!DEPENDENCY_CONFUSION_CONFIG.SCOPE_PATTERNS || !Array.isArray(DEPENDENCY_CONFUSION_CONFIG.SCOPE_PATTERNS.PRIVATE_SCOPES)) {
    errors.push('DEPENDENCY_CONFUSION_CONFIG.SCOPE_PATTERNS must define PRIVATE_SCOPES (array)');
  }
  const mlCfg = DEPENDENCY_CONFUSION_CONFIG.ML_DETECTION;
  if (mlCfg && mlCfg.ML_WEIGHTS) {
    const sum = Object.values(mlCfg.ML_WEIGHTS).reduce((a, b) => a + (typeof b === 'number' ? b : 0), 0);
    if (sum > 0 && (sum < 0.5 || sum > 1.5)) {
      errors.push(`ML_DETECTION.ML_WEIGHTS sum is ${sum.toFixed(2)}; typical range 0.5–1.5 for 0–1 score`);
    }
  }
}

if (!CACHE_CONFIG || typeof CACHE_CONFIG.TTL !== 'number') {
  errors.push('CACHE_CONFIG.TTL must be a number');
}

if (!VALIDATION_CONFIG || !Array.isArray(VALIDATION_CONFIG.ALLOWED_EXTENSIONS)) {
  errors.push('VALIDATION_CONFIG must define ALLOWED_EXTENSIONS (array)');
}

if (errors.length > 0) {
  errors.forEach((e) => console.error('Config error:', e));
  process.exit(1);
}

console.log('Config validation OK');
process.exit(0);
