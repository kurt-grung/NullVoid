/**
 * Canonical ML feature key order for dependency and behavioral XGBoost models.
 * Source of truth: ml-model/feature-keys.json (loaded at build time).
 */

import manifest from '../../../ml-model/feature-keys.json';

export const ML_FEATURE_SCHEMA_VERSION = manifest.version as number;

/** Column order for POST /score (dependency model). */
export const ML_DEPENDENCY_MODEL_FEATURE_KEYS = manifest.dependency as readonly string[];

/** Column order for POST /behavioral-score. */
export const ML_BEHAVIORAL_MODEL_FEATURE_KEYS = manifest.behavioral as readonly string[];
