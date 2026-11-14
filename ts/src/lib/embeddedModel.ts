import * as fs from 'fs';
import * as path from 'path';

const MODEL_CANDIDATES = [
  path.join(process.cwd(), 'ml-model', 'model.model.json'),
  path.resolve(__dirname, '../../../ml-model/model.model.json'),
];

export function embeddedModelArtifactExists(): boolean {
  return MODEL_CANDIDATES.some((p) => fs.existsSync(p));
}

/**
 * Base URL of the ML scoring service. An explicit ML_SERVICE_URL (e.g. the Vercel service
 * binding) always wins; otherwise a local server is assumed only when the model artifacts
 * are present next to the code.
 */
export function resolveEmbeddedMlServiceUrl(): string | null {
  const fromEnv = process.env['ML_SERVICE_URL']?.replace(/\/$/, '');
  if (fromEnv) return fromEnv;
  if (!embeddedModelArtifactExists()) return null;
  return 'http://127.0.0.1:8000';
}

export function readEmbeddedModelVersion(): string | null {
  const metaPaths = [
    path.join(process.cwd(), 'ml-model', 'metadata.json'),
    path.resolve(__dirname, '../../../ml-model/metadata.json'),
  ];
  for (const metaPath of metaPaths) {
    try {
      const raw = fs.readFileSync(metaPath, 'utf8');
      const meta = JSON.parse(raw) as { version?: string; trained_at?: string };
      return meta.version ?? meta.trained_at ?? null;
    } catch {
      /* try next */
    }
  }
  return null;
}
