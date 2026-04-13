/**
 * NullVoid REST API
 * POST /scan, GET /scan/:id, GET /scans
 * GET /organizations, GET /teams - multi-tenant entities
 * Auth: X-API-Key or X-Organization-Id, X-Team-Id for tenant context
 */

import express, { Request, Response } from 'express';
import * as fs from 'fs';
import * as path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);
import {
  createOrganization,
  listOrganizations,
  getOrganization,
  createTeam,
  listTeams,
  getTeam,
  insertScan,
  updateScan,
  getScan,
  listScans,
} from './db';

/** Wrap async route handlers so rejections reach error middleware */
const asyncHandler =
  (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: (err?: unknown) => void) => {
    Promise.resolve(fn(req, res)).catch(next);
  };

/** Lazy-load scan module (heavy) - only when POST /scan runs */
function getScanFn(): (target: string, options?: object) => Promise<unknown> {
  const tsDist = path.resolve(__dirname, '../../../ts/dist');
  const scanModule = require(path.join(tsDist, 'scan'));
  return scanModule.scan;
}

const PORT = parseInt(process.env['PORT'] ?? process.env['NULLVOID_API_PORT'] ?? '3001', 10);
const API_KEY = process.env['NULLVOID_API_KEY'] ?? null;
const SCAN_ROOT = path.resolve(process.env['NULLVOID_SCAN_ROOT'] ?? process.cwd());

/** Platform detection: Railway sets RAILWAY_PROJECT_ID / RAILWAY_ENVIRONMENT_ID */
const isRailway = !!(process.env['RAILWAY_PROJECT_ID'] ?? process.env['RAILWAY_ENVIRONMENT_ID']);

const app = express();
// CORS: allow dashboard on Vercel (or other origins) to call API on Railway
const corsOrigin = process.env['CORS_ORIGIN'] ?? '*';
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', corsOrigin);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-API-Key, X-Organization-Id, X-Team-Id');
  if (req.method === 'OPTIONS') {
    res.sendStatus(204);
    return;
  }
  next();
});
// Strip /api prefix when behind Vercel proxy (requests come as /api/scan, etc.)
app.use((req, _res, next) => {
  if (req.url.startsWith('/api')) {
    req.url = req.url.slice(4) || '/';
  }
  next();
});
app.use(express.json());

function getTenantHeaders(req: Request): { organizationId?: string; teamId?: string } {
  return {
    organizationId: req.headers['x-organization-id'] as string | undefined,
    teamId: req.headers['x-team-id'] as string | undefined,
  };
}

function requireTenantHeaders(
  req: Request,
  res: Response
): { organizationId?: string; teamId?: string } | null {
  const tenant = getTenantHeaders(req);
  if (!API_KEY) return tenant;
  if (!tenant.organizationId) {
    res.status(400).json({
      error: 'X-Organization-Id is required when API key auth is enabled',
    });
    return null;
  }
  return tenant;
}

function sanitizeScanTarget(rawTarget: unknown): string {
  const candidate = typeof rawTarget === 'string' ? rawTarget.trim() : '.';
  const normalizedInput = candidate.length > 0 ? candidate : '.';
  if (normalizedInput.includes('\0')) {
    throw new Error('Target contains invalid null byte');
  }
  const resolved = path.isAbsolute(normalizedInput)
    ? path.resolve(normalizedInput)
    : path.resolve(SCAN_ROOT, normalizedInput);
  const relative = path.relative(SCAN_ROOT, resolved);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error(`Target must resolve inside configured scan root: ${SCAN_ROOT}`);
  }
  return resolved;
}

function parseResultJson(
  rawResultJson: string | null
): Record<string, unknown> | undefined {
  if (!rawResultJson) return undefined;
  try {
    return JSON.parse(rawResultJson) as Record<string, unknown>;
  } catch {
    return undefined;
  }
}

function authMiddleware(req: Request, res: Response, next: () => void): void {
  if (API_KEY) {
    const key = req.headers['x-api-key'] as string;
    if (key !== API_KEY) {
      res.status(401).json({ error: 'Invalid or missing X-API-Key' });
      return;
    }
  }
  next();
}

function requireAuth(req: Request, res: Response, next: () => void): void {
  if (!API_KEY) {
    next();
    return;
  }
  const key = req.headers['x-api-key'] as string;
  if (!key || key !== API_KEY) {
    res.status(401).json({ error: 'Invalid or missing X-API-Key' });
    return;
  }
  next();
}

app.use(authMiddleware);

/** GET / - API info (avoids "Cannot GET /api" when visiting /api directly) */
app.get('/', (_req: Request, res: Response) => {
  res.json({
    name: 'NullVoid API',
    version: '1.0',
    endpoints: {
      health: 'GET /api/health',
      scans: 'GET /api/scans',
      scan: 'GET /api/scan/:id',
      triggerScan: 'POST /api/scan',
      report: 'GET /api/report/:scanId?format=html|markdown&compliance=soc2|iso27001',
      organizations: 'GET /api/organizations',
      teams: 'GET /api/teams',
      mlMetrics: 'GET /api/ml/metrics',
      mlDrift: 'GET /api/ml/drift',
    },
  });
});

function enforceTenantAccess(
  req: Request,
  orgId?: string | null,
  teamId?: string | null
): boolean {
  if (!API_KEY) return true;
  const { organizationId: reqOrg, teamId: reqTeam } = getTenantHeaders(req);
  if (!reqOrg || !orgId) return false;
  if (orgId !== reqOrg) return false;
  if (teamId && reqTeam !== teamId) return false;
  if (!teamId && reqTeam) return false;
  return true;
}

/** POST /scan - run scan synchronously (required for Vercel serverless; no background jobs) */
app.post(
  '/scan',
  requireAuth,
  asyncHandler(async (req: Request, res: Response) => {
    const tenant = requireTenantHeaders(req, res);
    if (!tenant) return;
    const { organizationId, teamId } = tenant;

    let target: string;
    try {
      target = sanitizeScanTarget(req.body?.target);
    } catch (error) {
      res.status(400).json({ error: (error as Error).message });
      return;
    }

    const id = `scan-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
    const createdAt = new Date().toISOString();
    await insertScan({
      id,
      organizationId,
      teamId,
      target,
      status: 'pending',
    });

    await updateScan(id, { status: 'running' });
    const scan = getScanFn();
    try {
      const result = await scan(target, { depth: 5 });
      const completedAt = new Date().toISOString();
      await updateScan(id, {
        status: 'completed',
        resultJson: JSON.stringify(result),
        completedAt,
      });
      res.status(200).json({
        id,
        status: 'completed',
        target,
        result,
        createdAt,
        completedAt,
      });
    } catch (err) {
      const msg = (err as Error).message;
      const completedAt = new Date().toISOString();
      await updateScan(id, {
        status: 'failed',
        error: msg,
        completedAt,
      });
      res.status(500).json({
        id,
        status: 'failed',
        target,
        error: 'Scan execution failed',
        createdAt,
        completedAt,
      });
    }
  })
);

/** GET /scan/:id - scan status/results */
app.get(
  '/scan/:id',
  asyncHandler(async (req: Request, res: Response) => {
    const tenant = requireTenantHeaders(req, res);
    if (!tenant) return;
    const row = await getScan(req.params.id);
    if (!row) {
      res.status(404).json({ error: 'Scan not found' });
      return;
    }
    if (!enforceTenantAccess(req, row.organization_id, row.team_id)) {
      res.status(403).json({ error: 'Forbidden' });
      return;
    }
    const result = parseResultJson(row.result_json);
    res.json({
      id: row.id,
      status: row.status,
      target: row.target,
      result,
      error: row.error,
      createdAt: row.created_at,
      completedAt: row.completed_at,
    });
  })
);

/** GET /scans - list scans (filter by org/team) */
app.get(
  '/scans',
  asyncHandler(async (req: Request, res: Response) => {
    const tenant = requireTenantHeaders(req, res);
    if (!tenant) return;
    const { organizationId, teamId } = tenant;

    const parsedLimit = parseInt(req.query.limit as string, 10);
    const limit = Number.isFinite(parsedLimit) ? Math.min(parsedLimit, 100) : 50;
    const rows = await listScans({ organizationId, teamId, limit });
    const scans = rows.map((r) => ({
      id: r.id,
      status: r.status,
      target: r.target,
      organizationId: r.organization_id,
      teamId: r.team_id,
      createdAt: r.created_at,
      completedAt: r.completed_at,
    }));
    res.json({ scans });
  })
);

/** GET /report/:scanId - HTML or Markdown report (?format=html|markdown&compliance=soc2|iso27001) */
app.get(
  '/report/:scanId',
  asyncHandler(async (req: Request, res: Response) => {
    const tenant = requireTenantHeaders(req, res);
    if (!tenant) return;
    const row = await getScan(req.params.scanId);
    if (!row) {
      res.status(404).json({ error: 'Scan not found' });
      return;
    }
    if (!enforceTenantAccess(req, row.organization_id, row.team_id)) {
      res.status(403).json({ error: 'Forbidden' });
      return;
    }
    const result = parseResultJson(row.result_json);
    if (row.result_json && !result) {
      res.status(500).json({ error: 'Stored scan result is invalid JSON' });
      return;
    }
    if (!result || row.status !== 'completed') {
      res.status(400).json({ error: 'Scan not completed or no result' });
      return;
    }
    if (!result.metadata) result.metadata = {};
    (result.metadata as Record<string, unknown>)['target'] = (result.metadata as Record<string, unknown>)['target'] ?? row.target;

    const format = (req.query.format as string) || 'html';
    const compliance = req.query.compliance as 'soc2' | 'iso27001' | undefined;
    const opts = compliance ? { compliance } : undefined;

    const tsDist = path.resolve(__dirname, '../../../ts/dist');
    const reporting = require(path.join(tsDist, 'lib/reporting')) as {
      generateHtmlReport: (r: unknown, o?: { compliance?: 'soc2' | 'iso27001' }) => string;
      generateMarkdownReport: (r: unknown, o?: { compliance?: 'soc2' | 'iso27001' }) => string;
    };

    if (format === 'markdown') {
      const md = reporting.generateMarkdownReport(result, opts);
      res.setHeader('Content-Type', 'text/markdown');
      res.setHeader('Content-Disposition', `attachment; filename="nullvoid-${String(row.target).replace(/[^a-zA-Z0-9.-]/g, '_')}-report.md"`);
      res.send(md);
    } else {
      const html = reporting.generateHtmlReport(result, opts);
      res.setHeader('Content-Type', 'text/html');
      res.send(html);
    }
  })
);

/** GET /organizations - list organizations */
app.get(
  '/organizations',
  asyncHandler(async (_req: Request, res: Response) => {
    const orgs = await listOrganizations();
    res.json({ organizations: orgs });
  })
);

/** GET /organizations/:id - get organization */
app.get(
  '/organizations/:id',
  asyncHandler(async (req: Request, res: Response) => {
    const org = await getOrganization(req.params.id);
    if (!org) {
      res.status(404).json({ error: 'Organization not found' });
      return;
    }
    res.json(org);
  })
);

/** POST /organizations - create organization */
app.post(
  '/organizations',
  requireAuth,
  asyncHandler(async (req: Request, res: Response) => {
    const name = (req.body?.name as string) ?? 'Default';
    const org = await createOrganization(name);
    res.status(201).json(org);
  })
);

/** GET /teams - list teams (optional ?organizationId=) */
app.get(
  '/teams',
  asyncHandler(async (req: Request, res: Response) => {
    const orgId = req.query.organizationId as string | undefined;
    const teams = await listTeams(orgId);
    res.json({ teams });
  })
);

/** GET /teams/:id - get team */
app.get(
  '/teams/:id',
  asyncHandler(async (req: Request, res: Response) => {
    const team = await getTeam(req.params.id);
    if (!team) {
      res.status(404).json({ error: 'Team not found' });
      return;
    }
    res.json(team);
  })
);

/** POST /teams - create team (requires organizationId in body) */
app.post(
  '/teams',
  requireAuth,
  asyncHandler(async (req: Request, res: Response) => {
    const organizationId = req.body?.organizationId as string;
    const name = (req.body?.name as string) ?? 'Default';
    if (!organizationId) {
      res.status(400).json({ error: 'organizationId required' });
      return;
    }
    const org = await getOrganization(organizationId);
    if (!org) {
      res.status(404).json({ error: 'Organization not found' });
      return;
    }
    const team = await createTeam(organizationId, name);
    res.status(201).json(team);
  })
);

/** GET /health - optional ?platform=1 for platform info */
app.get('/health', (req: Request, res: Response) => {
  const body: { ok: boolean; platform?: string } = { ok: true };
  if (req.query.platform === '1') {
    body.platform = isRailway ? 'railway' : process.env['VERCEL'] === '1' ? 'vercel' : 'local';
  }
  res.json(body);
});

/** ML commands - only available when API runs locally or on Railway (not on Vercel) */
const ML_AVAILABLE = process.env['VERCEL'] !== '1';
const ROOT = path.resolve(__dirname, '../../..');

async function runMlCommand(cmd: string): Promise<{ stdout: string; stderr: string }> {
  const { stdout, stderr } = await execAsync(cmd, {
    cwd: ROOT,
    maxBuffer: 10 * 1024 * 1024,
  });
  return { stdout, stderr };
}

app.post(
  '/ml/export',
  requireAuth,
  asyncHandler(async (_req: Request, res: Response) => {
    if (!ML_AVAILABLE) {
      res.status(503).json({
        error: 'ML commands only available when running API locally',
        hint: 'Run `make api` and use the dashboard at localhost:5174',
      });
      return;
    }
    try {
      const { stdout, stderr } = await runMlCommand('node ts/dist/bin/nullvoid.js export');
      res.json({ ok: true, stdout: stdout.trim(), stderr: stderr.trim() });
    } catch (err) {
      const e = err as { stdout?: string; stderr?: string; message?: string };
      res.status(500).json({
        error: e.message ?? 'Export failed',
        stdout: e.stdout?.trim(),
        stderr: e.stderr?.trim(),
      });
    }
  })
);

app.post(
  '/ml/train',
  requireAuth,
  asyncHandler(async (_req: Request, res: Response) => {
    if (!ML_AVAILABLE) {
      res.status(503).json({
        error: 'ML commands only available when running API locally',
        hint: 'Run `make api` and use the dashboard at localhost:5174',
      });
      return;
    }
    try {
      const { stdout, stderr } = await runMlCommand('node ts/dist/bin/nullvoid.js train');
      res.json({ ok: true, stdout: stdout.trim(), stderr: stderr.trim() });
    } catch (err) {
      const e = err as { stdout?: string; stderr?: string; message?: string };
      res.status(500).json({
        error: e.message ?? 'Train failed',
        stdout: e.stdout?.trim(),
        stderr: e.stderr?.trim(),
      });
    }
  })
);

app.post(
  '/ml/export-behavioral',
  requireAuth,
  asyncHandler(async (_req: Request, res: Response) => {
    if (!ML_AVAILABLE) {
      res.status(503).json({
        error: 'ML commands only available when running API locally',
        hint: 'Run `make api` and use the dashboard at localhost:5174',
      });
      return;
    }
    try {
      const { stdout, stderr } = await runMlCommand(
        'node ts/dist/bin/nullvoid.js export-behavioral'
      );
      res.json({ ok: true, stdout: stdout.trim(), stderr: stderr.trim() });
    } catch (err) {
      const e = err as { stdout?: string; stderr?: string; message?: string };
      res.status(500).json({
        error: e.message ?? 'Export behavioral failed',
        stdout: e.stdout?.trim(),
        stderr: e.stderr?.trim(),
      });
    }
  })
);

app.post(
  '/ml/train-behavioral',
  requireAuth,
  asyncHandler(async (_req: Request, res: Response) => {
    if (!ML_AVAILABLE) {
      res.status(503).json({
        error: 'ML commands only available when running API locally',
        hint: 'Run `make api` and use the dashboard at localhost:5174',
      });
      return;
    }
    try {
      const { stdout, stderr } = await runMlCommand('node ts/dist/bin/nullvoid.js train-behavioral');
      res.json({ ok: true, stdout: stdout.trim(), stderr: stderr.trim() });
    } catch (err) {
      const e = err as { stdout?: string; stderr?: string; message?: string };
      res.status(500).json({
        error: e.message ?? 'Train behavioral failed',
        stdout: e.stdout?.trim(),
        stderr: e.stderr?.trim(),
      });
    }
  })
);

/** GET /ml/metrics - last training metadata from ml-model/ (local clone); CI held-out metrics are in the ml-eval-report artifact */
app.get(
  '/ml/metrics',
  asyncHandler(async (_req: Request, res: Response) => {
    const mlDir = path.join(ROOT, 'ml-model');
    const readJson = (name: string): Record<string, unknown> | null => {
      try {
        const raw = fs.readFileSync(path.join(mlDir, name), 'utf8');
        return JSON.parse(raw) as Record<string, unknown>;
      } catch {
        return null;
      }
    };
    res.json({
      dependency: readJson('metadata.json'),
      behavioral: readJson('behavioral-metadata.json'),
      hint: 'Figures are from the last train run on this machine (incl. train.py internal holdout when data allows). GitHub Actions uploads held-out validation metrics as the ml-eval-report artifact.',
    });
  })
);

app.get(
  '/ml/status',
  asyncHandler(async (_req: Request, res: Response) => {
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
        'Set ML_SERVICE_URL (e.g. https://your-ml.up.railway.app) or run nullvoid serve / make serve on port 8000';
    }
    res.json({
      available: ML_AVAILABLE,
      hint: ML_AVAILABLE ? undefined : 'ML commands only work when API runs locally (make api)',
      serveAvailable,
      serveHint: serveAvailable ? undefined : serveHint,
      serveShapAvailable,
      serveNote: serveAvailable ? serveNote : undefined,
      mlServiceUrl: mlServiceUrl ?? null,
    });
  })
);

app.get(
  '/ml/drift',
  asyncHandler(async (_req: Request, res: Response) => {
    const mlServiceUrl = process.env['ML_SERVICE_URL']?.replace(/\/$/, '');
    if (!mlServiceUrl) {
      res.status(503).json({ error: 'ML_SERVICE_URL not configured' });
      return;
    }
    try {
      const r = await fetch(`${mlServiceUrl}/drift`, { signal: AbortSignal.timeout(4000) });
      if (!r.ok) {
        res.status(502).json({ error: `ML service drift endpoint returned ${r.status}` });
        return;
      }
      const data = (await r.json()) as Record<string, unknown>;
      res.json(data);
    } catch (error) {
      res.status(502).json({
        error: 'Unable to fetch drift data from ML service',
        details: (error as Error).message,
      });
    }
  })
);

app.post(
  '/ml/feedback',
  requireAuth,
  asyncHandler(async (req: Request, res: Response) => {
    const packageName = req.body?.packageName as string | undefined;
    const version = req.body?.version as string | undefined;
    const label = req.body?.label as number | undefined;
    const scanId = req.body?.scanId as string | undefined;
    if (!packageName || !version || (label !== 0 && label !== 1) || !scanId) {
      res.status(400).json({
        error: 'Invalid payload. Expected { packageName, version, label: 0|1, scanId }',
      });
      return;
    }
    const feedbackPath = path.join(ROOT, 'ml-model', 'feedback.jsonl');
    const row = {
      packageName,
      version,
      label,
      scanId,
      createdAt: new Date().toISOString(),
    };
    fs.appendFileSync(feedbackPath, JSON.stringify(row) + '\n', 'utf8');
    res.json({ ok: true, path: feedbackPath });
  })
);

/** Error handler: return 503 for missing Turso config on Vercel/Railway */
app.use((err: unknown, _req: Request, res: Response, next: (err?: unknown) => void) => {
  const e = err as Error & { code?: string };
  if (e?.code === 'TURSO_CONFIG_MISSING') {
    const tursoHint = isRailway
      ? 'Add TURSO_DATABASE_URL and TURSO_AUTH_TOKEN in Railway → Variables.'
      : 'Add TURSO_DATABASE_URL and TURSO_AUTH_TOKEN in Vercel → Settings → Environment Variables.';
    res.status(503).json({
      error: 'Database not configured',
      message: e.message,
      hint: tursoHint,
    });
    return;
  }
  next(err);
});

/** Final error handler: always send response to prevent FUNCTION_INVOCATION_FAILED */
app.use((err: unknown, _req: Request, res: Response, _next: () => void) => {
  if (res.headersSent) return;
  const logHint = isRailway
    ? 'Check Railway logs for details.'
    : process.env['VERCEL']
      ? 'Check Vercel logs for details.'
      : 'Check local server logs for details.';
  res.status(500).json({
    error: 'Internal server error',
    message: logHint,
  });
});

module.exports = app;

// Listen only when this file is executed directly.
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`NullVoid API listening on port ${PORT}`);
  });
}
