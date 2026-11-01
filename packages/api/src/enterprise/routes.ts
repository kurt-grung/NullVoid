import type { Express, Request, Response } from 'express';
import * as crypto from 'crypto';
import {
  appendAudit,
  createSchedule,
  createWebhook,
  deleteSchedule,
  deleteWebhook,
  dispatchWebhooks,
  listAudit,
  listSchedules,
  listWebhooks,
} from './store';
import type { RbacRole } from './types';
import { roleCanManageWebhooks, roleCanTriggerScan, roleCanViewAudit } from './types';

function getRole(req: Request): RbacRole {
  const header = req.header('X-NullVoid-Role');
  if (header === 'admin' || header === 'analyst' || header === 'viewer') return header;
  return 'admin';
}

function auditFromRequest(
  req: Request,
  action: Parameters<typeof appendAudit>[0]['action'],
  resourceType?: string,
  resourceId?: string,
  details?: Record<string, unknown>
): void {
  appendAudit({
    id: `audit-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    organizationId: req.header('X-Organization-Id') ?? null,
    teamId: req.header('X-Team-Id') ?? null,
    actor: req.header('X-API-Key') ? 'api-key' : 'anonymous',
    action,
    resourceType,
    resourceId,
    details,
    createdAt: new Date().toISOString(),
  });
}

export function registerEnterpriseRoutes(app: Express, requireAuth: (_req: Request, res: Response, next: () => void) => void): void {
  app.get('/schedules', requireAuth, (req: Request, res: Response) => {
    const orgId = req.header('X-Organization-Id') ?? null;
    res.json({ schedules: listSchedules(orgId) });
  });

  app.post('/schedule', requireAuth, (req: Request, res: Response) => {
    const role = getRole(req);
    if (!roleCanTriggerScan(role)) {
      res.status(403).json({ error: 'Forbidden' });
      return;
    }
    const target = req.body?.target as string | undefined;
    const cronExpression = req.body?.cronExpression as string | undefined;
    if (!target || !cronExpression) {
      res.status(400).json({ error: 'target and cronExpression required' });
      return;
    }
    const entry = createSchedule({
      id: `sched-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      organizationId: req.header('X-Organization-Id') ?? null,
      teamId: req.header('X-Team-Id') ?? null,
      target,
      cronExpression,
      enabled: true,
      nextRunAt: null,
      createdAt: new Date().toISOString(),
    });
    auditFromRequest(req, 'schedule.created', 'schedule', entry.id, { target, cronExpression });
    res.status(201).json(entry);
  });

  app.delete('/schedule/:id', requireAuth, (req: Request, res: Response) => {
    const role = getRole(req);
    if (!roleCanTriggerScan(role)) {
      res.status(403).json({ error: 'Forbidden' });
      return;
    }
    const ok = deleteSchedule(req.params.id);
    if (!ok) {
      res.status(404).json({ error: 'Schedule not found' });
      return;
    }
    auditFromRequest(req, 'schedule.deleted', 'schedule', req.params.id);
    res.json({ ok: true });
  });

  app.get('/webhooks', requireAuth, (req: Request, res: Response) => {
    const orgId = req.header('X-Organization-Id') ?? null;
    const hooks = listWebhooks(orgId).map(({ secret: _s, ...rest }) => rest);
    res.json({ webhooks: hooks });
  });

  app.post('/webhooks', requireAuth, (req: Request, res: Response) => {
    const role = getRole(req);
    if (!roleCanManageWebhooks(role)) {
      res.status(403).json({ error: 'Forbidden' });
      return;
    }
    const url = req.body?.url as string | undefined;
    const events = req.body?.events as string[] | undefined;
    if (!url || !Array.isArray(events) || events.length === 0) {
      res.status(400).json({ error: 'url and events[] required' });
      return;
    }
    const secret = crypto.randomBytes(32).toString('hex');
    const entry = createWebhook({
      id: `wh-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      organizationId: req.header('X-Organization-Id') ?? null,
      url,
      secret,
      events,
      enabled: true,
      createdAt: new Date().toISOString(),
    });
    auditFromRequest(req, 'webhook.created', 'webhook', entry.id, { url, events });
    res.status(201).json({ ...entry, secret });
  });

  app.delete('/webhooks/:id', requireAuth, (req: Request, res: Response) => {
    const role = getRole(req);
    if (!roleCanManageWebhooks(role)) {
      res.status(403).json({ error: 'Forbidden' });
      return;
    }
    const ok = deleteWebhook(req.params.id);
    if (!ok) {
      res.status(404).json({ error: 'Webhook not found' });
      return;
    }
    auditFromRequest(req, 'webhook.deleted', 'webhook', req.params.id);
    res.json({ ok: true });
  });

  app.get('/audit', requireAuth, (req: Request, res: Response) => {
    const role = getRole(req);
    if (!roleCanViewAudit(role)) {
      res.status(403).json({ error: 'Forbidden' });
      return;
    }
    const orgId = req.header('X-Organization-Id') ?? null;
    const limit = Math.min(parseInt(String(req.query.limit ?? '100'), 10) || 100, 500);
    res.json({ entries: listAudit(orgId, limit) });
  });

  app.get('/graphql', (_req: Request, res: Response) => {
    res.json({
      message: 'GraphQL endpoint planned; use REST /scans and /scan/:id for now.',
      plannedQueries: ['scans', 'scan', 'threats', 'trends'],
    });
  });

  app.get('/scan/:id/events', requireAuth, (req: Request, res: Response) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.write(`data: ${JSON.stringify({ scanId: req.params.id, status: 'connected' })}\n\n`);
    const interval = setInterval(() => {
      res.write(`data: ${JSON.stringify({ scanId: req.params.id, heartbeat: Date.now() })}\n\n`);
    }, 15000);
    req.on('close', () => clearInterval(interval));
  });
}

export { dispatchWebhooks, appendAudit };
