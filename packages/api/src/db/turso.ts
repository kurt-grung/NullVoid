/**
 * Turso (libSQL) adapter for Vercel serverless
 * Use when TURSO_DATABASE_URL is set
 */

import { createClient } from '@libsql/client';
import { SCHEMA } from './schema';
import type { Organization, Team, ScanRow } from './types';

let client: ReturnType<typeof createClient> | null = null;

function getClient() {
  if (!client) {
    const url = (process.env['TURSO_DATABASE_URL'] ?? '').trim();
    const authToken = (process.env['TURSO_AUTH_TOKEN'] ?? '').trim();
    if (!url || !authToken) {
      const err = new Error(
        'TURSO_DATABASE_URL and TURSO_AUTH_TOKEN required. Add them in Vercel → Settings → Environment Variables (Production + Preview).'
      ) as Error & { code?: string };
      err.code = 'TURSO_CONFIG_MISSING';
      throw err;
    }
    client = createClient({ url, authToken });
  }
  return client;
}

async function initSchema() {
  const c = getClient();
  const statements = SCHEMA.split(';')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  for (const stmt of statements) {
    await c.execute(stmt + ';');
  }
}

let schemaInit: Promise<void> | null = null;
async function ensureSchema() {
  if (!schemaInit) schemaInit = initSchema();
  await schemaInit;
}

export async function createOrganization(name: string): Promise<Organization> {
  await ensureSchema();
  const id = `org-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  const c = getClient();
  await c.execute({
    sql: 'INSERT INTO organizations (id, name) VALUES (?, ?)',
    args: [id, name],
  });
  const r = await c.execute({ sql: 'SELECT * FROM organizations WHERE id = ?', args: [id] });
  return r.rows[0] as unknown as Organization;
}

export async function listOrganizations(): Promise<Organization[]> {
  await ensureSchema();
  const r = await getClient().execute('SELECT * FROM organizations ORDER BY created_at DESC');
  return r.rows as unknown as Organization[];
}

export async function getOrganization(id: string): Promise<Organization | undefined> {
  await ensureSchema();
  const r = await getClient().execute({ sql: 'SELECT * FROM organizations WHERE id = ?', args: [id] });
  return (r.rows[0] as unknown as Organization) ?? undefined;
}

export async function createTeam(organizationId: string, name: string): Promise<Team> {
  await ensureSchema();
  const id = `team-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  const c = getClient();
  await c.execute({
    sql: 'INSERT INTO teams (id, organization_id, name) VALUES (?, ?, ?)',
    args: [id, organizationId, name],
  });
  const r = await c.execute({ sql: 'SELECT * FROM teams WHERE id = ?', args: [id] });
  return r.rows[0] as unknown as Team;
}

export async function listTeams(organizationId?: string): Promise<Team[]> {
  await ensureSchema();
  const c = getClient();
  const r = organizationId
    ? await c.execute({
        sql: 'SELECT * FROM teams WHERE organization_id = ? ORDER BY created_at DESC',
        args: [organizationId],
      })
    : await c.execute('SELECT * FROM teams ORDER BY created_at DESC');
  return r.rows as unknown as Team[];
}

export async function getTeam(id: string): Promise<Team | undefined> {
  await ensureSchema();
  const r = await getClient().execute({ sql: 'SELECT * FROM teams WHERE id = ?', args: [id] });
  return (r.rows[0] as unknown as Team) ?? undefined;
}

export async function insertScan(row: {
  id: string;
  organizationId?: string;
  teamId?: string;
  target: string;
  status: string;
}): Promise<void> {
  await ensureSchema();
  await getClient().execute({
    sql: 'INSERT INTO scans (id, organization_id, team_id, target, status) VALUES (?, ?, ?, ?, ?)',
    args: [row.id, row.organizationId ?? null, row.teamId ?? null, row.target, row.status],
  });
}

export async function updateScan(
  id: string,
  updates: { status: string; resultJson?: string; error?: string; completedAt?: string }
): Promise<void> {
  await ensureSchema();
  await getClient().execute({
    sql: 'UPDATE scans SET status = ?, result_json = ?, error = ?, completed_at = ? WHERE id = ?',
    args: [
      updates.status,
      updates.resultJson ?? null,
      updates.error ?? null,
      updates.completedAt ?? null,
      id,
    ],
  });
}

export async function getScan(id: string): Promise<ScanRow | undefined> {
  await ensureSchema();
  const r = await getClient().execute({ sql: 'SELECT * FROM scans WHERE id = ?', args: [id] });
  const row = r.rows[0];
  if (!row) return undefined;
  return {
    id: row.id,
    organization_id: row.organization_id,
    team_id: row.team_id,
    target: row.target,
    status: row.status,
    result_json: row.result_json,
    error: row.error,
    created_at: row.created_at,
    completed_at: row.completed_at,
  } as ScanRow;
}

export async function listScans(options: {
  organizationId?: string;
  teamId?: string;
  limit?: number;
}): Promise<ScanRow[]> {
  await ensureSchema();
  const { organizationId, teamId, limit = 50 } = options;
  const l = Math.min(limit, 100);
  const c = getClient();
  let r;
  if (organizationId && teamId) {
    r = await c.execute({
      sql: 'SELECT * FROM scans WHERE organization_id = ? AND team_id = ? ORDER BY created_at DESC LIMIT ?',
      args: [organizationId, teamId, l],
    });
  } else if (organizationId) {
    r = await c.execute({
      sql: 'SELECT * FROM scans WHERE organization_id = ? ORDER BY created_at DESC LIMIT ?',
      args: [organizationId, l],
    });
  } else if (teamId) {
    r = await c.execute({
      sql: 'SELECT * FROM scans WHERE team_id = ? ORDER BY created_at DESC LIMIT ?',
      args: [teamId, l],
    });
  } else {
    r = await c.execute({
      sql: 'SELECT * FROM scans ORDER BY created_at DESC LIMIT ?',
      args: [l],
    });
  }
  return r.rows.map((row) => ({
    id: row.id,
    organization_id: row.organization_id,
    team_id: row.team_id,
    target: row.target,
    status: row.status,
    result_json: row.result_json,
    error: row.error,
    created_at: row.created_at,
    completed_at: row.completed_at,
  })) as ScanRow[];
}
