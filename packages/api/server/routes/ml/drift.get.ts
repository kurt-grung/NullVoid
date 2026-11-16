import { defineHandler } from 'nitro';
import { fail } from '../../utils/http';

/** GET /ml/drift - proxy the ML service's drift report */
export default defineHandler(async () => {
  const mlServiceUrl = process.env['ML_SERVICE_URL']?.replace(/\/$/, '');
  if (!mlServiceUrl) fail(503, { error: 'ML_SERVICE_URL not configured' });
  let r: Response;
  try {
    r = await fetch(`${mlServiceUrl}/drift`, { signal: AbortSignal.timeout(4000) });
  } catch (error) {
    fail(502, { error: 'Unable to fetch drift data from ML service', details: (error as Error).message });
  }
  if (!r.ok) fail(502, { error: `ML service drift endpoint returned ${r.status}` });
  try {
    return (await r.json()) as Record<string, unknown>;
  } catch (error) {
    fail(502, { error: 'Unable to fetch drift data from ML service', details: (error as Error).message });
  }
});
