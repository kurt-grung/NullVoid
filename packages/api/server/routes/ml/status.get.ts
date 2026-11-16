import { defineHandler } from 'nitro';
import { ML_AVAILABLE } from '../../utils/config';

/** GET /ml/status - ML command availability and scorer service health */
export default defineHandler(async () => {
  const mlServiceUrl = process.env['ML_SERVICE_URL']?.replace(/\/$/, '');
  let serveAvailable = false;
  let serveHint: string | undefined;
  let serveShapAvailable: boolean | undefined;
  let serveNote: string | undefined;
  if (mlServiceUrl) {
    try {
      const r = await fetch(`${mlServiceUrl}/health`, { signal: AbortSignal.timeout(3000) });
      serveAvailable = r.ok;
      if (!r.ok) serveHint = `ML service at ${mlServiceUrl} returned ${r.status}`;
      else {
        try {
          const h = (await r.json()) as { shap?: boolean };
          if (typeof h['shap'] === 'boolean') {
            serveShapAvailable = h['shap'];
            if (!h['shap']) {
              serveNote =
                'Scorer is up without SHAP. For TreeExplainer-backed POST /explain, run: pip install -r ml-model/requirements-optional.txt on the ML host.';
            }
          }
        } catch {
          /* ignore non-JSON health */
        }
      }
    } catch {
      serveHint = `ML service at ${mlServiceUrl} is not reachable`;
    }
  } else {
    serveHint =
      'ML_SERVICE_URL is unset: on Vercel it comes from the ml-model service binding in vercel.json; locally, run nullvoid serve / make serve on port 8000';
  }
  return {
    available: ML_AVAILABLE,
    hint: ML_AVAILABLE ? undefined : 'ML commands only work when API runs locally (make api)',
    serveAvailable,
    serveHint: serveAvailable ? undefined : serveHint,
    serveShapAvailable,
    serveNote: serveAvailable ? serveNote : undefined,
    mlServiceUrl: mlServiceUrl ?? null,
  };
});
