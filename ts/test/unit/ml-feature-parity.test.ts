/**
 * Ensures TS ML feature order matches ml-model/feature-keys.json (Python / serve).
 */

import * as fs from 'fs';
import * as path from 'path';
import { describe, it, expect } from '@jest/globals';
import {
  ML_BEHAVIORAL_MODEL_FEATURE_KEYS,
  ML_DEPENDENCY_MODEL_FEATURE_KEYS,
  ML_FEATURE_SCHEMA_VERSION,
} from '../../src/lib/mlFeatureKeys';

describe('ML feature schema parity', () => {
  const repoRoot = path.join(__dirname, '..', '..', '..');
  const manifestPath = path.join(repoRoot, 'ml-model', 'feature-keys.json');

  it('loads the same manifest as ml-model/feature-keys.json on disk', () => {
    const raw = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as {
      version: number;
      dependency: string[];
      behavioral: string[];
    };
    expect(ML_FEATURE_SCHEMA_VERSION).toBe(raw.version);
    expect([...ML_DEPENDENCY_MODEL_FEATURE_KEYS]).toEqual(raw.dependency);
    expect([...ML_BEHAVIORAL_MODEL_FEATURE_KEYS]).toEqual(raw.behavioral);
  });

  it('has unique ordered keys for each model', () => {
    expect(new Set(ML_DEPENDENCY_MODEL_FEATURE_KEYS).size).toBe(
      ML_DEPENDENCY_MODEL_FEATURE_KEYS.length
    );
    expect(new Set(ML_BEHAVIORAL_MODEL_FEATURE_KEYS).size).toBe(
      ML_BEHAVIORAL_MODEL_FEATURE_KEYS.length
    );
  });
});
