/**
 * NullVoid REST API
 * POST /scan, GET /scan/:id, GET /scans
 * GET /organizations, GET /teams - multi-tenant entities
 * Auth: X-API-Key or X-Organization-Id, X-Team-Id for tenant context
 */

import express, { Request, Response } from 'express';
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
    },
  });
});

function enforceTenantAccess(
  req: Request,
  orgId?: string | null,
  teamId?: string | null
): boolean {
  if (!API_KEY) return true;
  const reqOrg = req.headers['x-organization-id'] as string | undefined;
  const reqTeam = req.headers['x-team-id'] as string | undefined;
  if (orgId && reqOrg && orgId !== reqOrg) return false;
  if (teamId && reqTeam && teamId !== reqTeam) return false;
  return true;
}

/** POST /scan - run scan synchronously (required for Vercel serverless; no background jobs) */
app.post(
  '/scan',
  requireAuth,
  asyncHandler(async (req: Request, res: Response) => {
    const target = (req.body?.target as string) ?? '.';
    const organizationId = req.headers['x-organization-id'] as string | undefined;
    const teamId = req.headers['x-team-id'] as string | undefined;

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
        error: msg,
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
    const row = await getScan(req.params.id);
    if (!row) {
      res.status(404).json({ error: 'Scan not found' });
      return;
    }
    if (!enforceTenantAccess(req, row.organization_id, row.team_id)) {
      res.status(403).json({ error: 'Forbidden' });
      return;
    }
    const result = row.result_json ? JSON.parse(row.result_json) : undefined;
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
    const orgId = req.headers['x-organization-id'] as string | undefined;
    const teamId = req.headers['x-team-id'] as string | undefined;
    const limit = Math.min(parseInt(req.query.limit as string) || 50, 100);
    const rows = await listScans({ organizationId: orgId, teamId, limit });
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
    const row = await getScan(req.params.scanId);
    if (!row) {
      res.status(404).json({ error: 'Scan not found' });
      return;
    }
    if (!enforceTenantAccess(req, row.organization_id, row.team_id)) {
      res.status(403).json({ error: 'Forbidden' });
      return;
    }
    const result = row.result_json ? (JSON.parse(row.result_json) as Record<string, unknown>) : undefined;
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

/** GET /health */
app.get('/health', (_req: Request, res: Response) => {
  res.json({ ok: true });
});

/** ML commands - only available when API runs locally (not on Vercel) */
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
      const { stdout, stderr } = await runMlCommand('npm run ml:export');
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
      const { stdout, stderr } = await runMlCommand('npm run ml:train');
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
      const { stdout, stderr } = await runMlCommand('npm run ml:export-behavioral');
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
      const { stdout, stderr } = await runMlCommand('npm run ml:train-behavioral');
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

app.get('/ml/status', (_req: Request, res: Response) => {
  res.json({
    available: ML_AVAILABLE,
    hint: ML_AVAILABLE ? undefined : 'ML commands only work when API runs locally (make api)',
  });
});

/** Error handler: return 503 for missing Turso config on Vercel */
app.use((err: unknown, _req: Request, res: Response, next: (err?: unknown) => void) => {
  const e = err as Error & { code?: string };
  if (e?.code === 'TURSO_CONFIG_MISSING') {
    res.status(503).json({
      error: 'Database not configured',
      message: e.message,
      hint: 'Add TURSO_DATABASE_URL and TURSO_AUTH_TOKEN in Vercel → Settings → Environment Variables.',
    });
    return;
  }
  next(err);
});

/** Final error handler: always send response to prevent FUNCTION_INVOCATION_FAILED */
app.use((err: unknown, _req: Request, res: Response, _next: () => void) => {
  if (res.headersSent) return;
  const e = err as Error;
  res.status(500).json({
    error: 'Internal server error',
    message: process.env['VERCEL'] ? 'Check Vercel logs for details.' : (e?.message ?? 'Unknown error'),
  });
});

// Export for Vercel serverless; listen when running standalone
if (process.env['VERCEL'] === '1') {
  module.exports = app;
} else {
  app.listen(PORT, () => {
    console.log(`NullVoid API listening on port ${PORT}`);
  });
}
