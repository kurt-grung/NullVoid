export const ENTERPRISE_SCHEMA = `
CREATE TABLE IF NOT EXISTS schedules (
  id TEXT PRIMARY KEY,
  organization_id TEXT,
  team_id TEXT,
  target TEXT NOT NULL,
  cron_expression TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  next_run_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (organization_id) REFERENCES organizations(id),
  FOREIGN KEY (team_id) REFERENCES teams(id)
);

CREATE TABLE IF NOT EXISTS webhooks (
  id TEXT PRIMARY KEY,
  organization_id TEXT,
  url TEXT NOT NULL,
  secret TEXT NOT NULL,
  events TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (organization_id) REFERENCES organizations(id)
);

CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY,
  organization_id TEXT,
  team_id TEXT,
  actor TEXT,
  action TEXT NOT NULL,
  resource_type TEXT,
  resource_id TEXT,
  details_json TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_schedules_org ON schedules(organization_id);
CREATE INDEX IF NOT EXISTS idx_webhooks_org ON webhooks(organization_id);
CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_log(organization_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);
`;

export type AuditAction =
  | 'scan.triggered'
  | 'scan.completed'
  | 'schedule.created'
  | 'schedule.deleted'
  | 'webhook.created'
  | 'webhook.deleted'
  | 'config.changed';

export interface AuditEntry {
  id: string;
  organizationId?: string | null;
  teamId?: string | null;
  actor?: string | null;
  action: AuditAction;
  resourceType?: string;
  resourceId?: string;
  details?: Record<string, unknown>;
  createdAt: string;
}

export interface ScheduleEntry {
  id: string;
  organizationId?: string | null;
  teamId?: string | null;
  target: string;
  cronExpression: string;
  enabled: boolean;
  nextRunAt?: string | null;
  createdAt: string;
}

export interface WebhookEntry {
  id: string;
  organizationId?: string | null;
  url: string;
  secret: string;
  events: string[];
  enabled: boolean;
  createdAt: string;
}

export type RbacRole = 'admin' | 'analyst' | 'viewer';

export function roleCanTriggerScan(role: RbacRole): boolean {
  return role === 'admin' || role === 'analyst';
}

export function roleCanManageWebhooks(role: RbacRole): boolean {
  return role === 'admin';
}

export function roleCanViewAudit(role: RbacRole): boolean {
  return role === 'admin' || role === 'analyst';
}
