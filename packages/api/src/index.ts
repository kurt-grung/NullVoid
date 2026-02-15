/**
 * NullVoid REST API
 * POST /scan, GET /scan/:id, GET /scans
 * GET /organizations, GET /teams - multi-tenant entities
 * Auth: X-API-Key or X-Organization-Id, X-Team-Id for tenant context
 */

import express, { Request, Response } from 'express';
import * as path from 'path';
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

/** POST /scan - trigger scan, return job ID */
app.post(
  '/scan',
  requireAuth,
  asyncHandler(async (req: Request, res: Response) => {
    const target = (req.body?.target as string) ?? '.';
    const organizationId = req.headers['x-organization-id'] as string | undefined;
    const teamId = req.headers['x-team-id'] as string | undefined;

    const id = `scan-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
    await insertScan({
      id,
      organizationId,
      teamId,
      target,
      status: 'pending',
    });
    res.status(202).json({ id, status: 'pending', target });

    void updateScan(id, { status: 'running' });
    const scan = getScanFn();
    scan(target, { depth: 5 })
      .then(async (result) => {
        await updateScan(id, {
          status: 'completed',
          resultJson: JSON.stringify(result),
          completedAt: new Date().toISOString(),
        });
      })
      .catch(async (err) => {
        await updateScan(id, {
          status: 'failed',
          error: (err as Error).message,
          completedAt: new Date().toISOString(),
        });
      });
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

// Export for Vercel serverless; listen when running standalone
if (process.env['VERCEL'] === '1') {
  module.exports = app;
} else {
  app.listen(PORT, () => {
    console.log(`NullVoid API listening on port ${PORT}`);
  });
}
