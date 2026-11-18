import { defineHandler } from 'nitro';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { ROOT } from '../../utils/config';
import { fail, readJson } from '../../utils/http';

/** POST /ml/feedback - append a labelled example to ml-model/feedback.jsonl */
export default defineHandler(async (event) => {
  const body = await readJson(event);
  const packageName = body['packageName'] as string | undefined;
  const version = body['version'] as string | undefined;
  const label = body['label'] as number | undefined;
  const scanId = body['scanId'] as string | undefined;
  if (!packageName || !version || (label !== 0 && label !== 1) || !scanId) {
    fail(400, { error: 'Invalid payload. Expected { packageName, version, label: 0|1, scanId }' });
  }
  const feedbackPath = path.join(ROOT, 'ml-model', 'feedback.jsonl');
  const row = { packageName, version, label, scanId, createdAt: new Date().toISOString() };
  fs.appendFileSync(feedbackPath, JSON.stringify(row) + '\n', 'utf8');
  return { ok: true, path: feedbackPath };
});
