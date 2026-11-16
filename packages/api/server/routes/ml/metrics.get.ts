import { defineHandler } from 'nitro';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { ROOT } from '../../utils/config';

/** GET /ml/metrics - last training metadata from ml-model/ (local clone) */
export default defineHandler(() => {
  const mlDir = path.join(ROOT, 'ml-model');
  const readJson = (name: string): Record<string, unknown> | null => {
    try {
      return JSON.parse(fs.readFileSync(path.join(mlDir, name), 'utf8')) as Record<string, unknown>;
    } catch {
      return null;
    }
  };
  return {
    dependency: readJson('metadata.json'),
    behavioral: readJson('behavioral-metadata.json'),
    hint: 'Figures are from the last train run on this machine (incl. train.py internal holdout when data allows). GitHub Actions uploads held-out validation metrics as the ml-eval-report artifact.',
  };
});
