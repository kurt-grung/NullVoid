/**
 * SQLite (better-sqlite3) adapter for local development
 */

import Database from 'better-sqlite3';
import * as path from 'path';
import { SCHEMA } from './schema';
import type { Organization, Team, ScanRow } from './types';

const DB_PATH = process.env['NULLVOID_DB_PATH'] ?? path.join(process.cwd(), 'nullvoid.db');
let db: Database.Database | null = null;

function getDb(): Database.Database {
  if (!db) {
    db = new Database(DB_PATH);
    db.exec(SCHEMA);
  }
  return db;
}

export async function createOrganization(name: string): Promise<Organization> {
  const id = `org-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  const stmt = getDb().prepare(
    'INSERT INTO organizations (id, name) VALUES (?, ?) RETURNING *'
  );
  return stmt.get(id, name) as Organization;
}

export async function listOrganizations(): Promise<Organization[]> {
  const stmt = getDb().prepare('SELECT * FROM organizations ORDER BY created_at DESC');
  return stmt.all() as Organization[];
}

export async function getOrganization(id: string): Promise<Organization | undefined> {
  const stmt = getDb().prepare('SELECT * FROM organizations WHERE id = ?');
  return stmt.get(id) as Organization | undefined;
}

export async function createTeam(organizationId: string, name: string): Promise<Team> {
  const id = `team-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  const stmt = getDb().prepare(
    'INSERT INTO teams (id, organization_id, name) VALUES (?, ?, ?) RETURNING *'
  );
  return stmt.get(id, organizationId, name) as Team;
}

export async function listTeams(organizationId?: string): Promise<Team[]> {
  if (organizationId) {
    const stmt = getDb().prepare(
      'SELECT * FROM teams WHERE organization_id = ? ORDER BY created_at DESC'
    );
    return stmt.all(organizationId) as Team[];
  }
  const stmt = getDb().prepare('SELECT * FROM teams ORDER BY created_at DESC');
  return stmt.all() as Team[];
}

export async function getTeam(id: string): Promise<Team | undefined> {
  const stmt = getDb().prepare('SELECT * FROM teams WHERE id = ?');
  return stmt.get(id) as Team | undefined;
}

export async function insertScan(row: {
  id: string;
  organizationId?: string;
  teamId?: string;
  target: string;
  status: string;
}): Promise<void> {
  const stmt = getDb().prepare(
    'INSERT INTO scans (id, organization_id, team_id, target, status) VALUES (?, ?, ?, ?, ?)'
  );
  stmt.run(row.id, row.organizationId ?? null, row.teamId ?? null, row.target, row.status);
}

export async function updateScan(
  id: string,
  updates: { status: string; resultJson?: string; error?: string; completedAt?: string }
): Promise<void> {
  const stmt = getDb().prepare(
    'UPDATE scans SET status = ?, result_json = ?, error = ?, completed_at = ? WHERE id = ?'
  );
  stmt.run(
    updates.status,
    updates.resultJson ?? null,
    updates.error ?? null,
    updates.completedAt ?? null,
    id
  );
}

export async function getScan(id: string): Promise<ScanRow | undefined> {
  const stmt = getDb().prepare('SELECT * FROM scans WHERE id = ?');
  return stmt.get(id) as ScanRow | undefined;
}

export async function listScans(options: {
  organizationId?: string;
  teamId?: string;
  limit?: number;
}): Promise<ScanRow[]> {
  const { organizationId, teamId, limit = 50 } = options;
  const l = Math.min(limit, 100);
  if (organizationId && teamId) {
    const stmt = getDb().prepare(
      'SELECT * FROM scans WHERE organization_id = ? AND team_id = ? ORDER BY created_at DESC LIMIT ?'
    );
    return stmt.all(organizationId, teamId, l) as ScanRow[];
  }
  if (organizationId) {
    const stmt = getDb().prepare(
      'SELECT * FROM scans WHERE organization_id = ? ORDER BY created_at DESC LIMIT ?'
    );
    return stmt.all(organizationId, l) as ScanRow[];
  }
  if (teamId) {
    const stmt = getDb().prepare(
      'SELECT * FROM scans WHERE team_id = ? ORDER BY created_at DESC LIMIT ?'
    );
    return stmt.all(teamId, l) as ScanRow[];
  }
  const stmt = getDb().prepare('SELECT * FROM scans ORDER BY created_at DESC LIMIT ?');
  return stmt.all(l) as ScanRow[];
}
