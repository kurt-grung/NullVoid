/**
 * DB layer: SQLite (local) or Turso (Vercel)
 * Uses Turso when TURSO_DATABASE_URL is set
 */

import type { Organization, Team, ScanRow } from './types';
export type { Organization, Team, ScanRow } from './types';

const useTurso = !!process.env['TURSO_DATABASE_URL'];

async function getSqliteDb() {
  const mod = await import('./sqlite');
  return mod;
}

async function getTursoDb() {
  return await import('./turso');
}

async function db() {
  return useTurso ? getTursoDb() : getSqliteDb();
}

export async function createOrganization(name: string): Promise<Organization> {
  return (await db()).createOrganization(name);
}

export async function listOrganizations(): Promise<Organization[]> {
  return (await db()).listOrganizations();
}

export async function getOrganization(id: string): Promise<Organization | undefined> {
  return (await db()).getOrganization(id);
}

export async function createTeam(organizationId: string, name: string): Promise<Team> {
  return (await db()).createTeam(organizationId, name);
}

export async function listTeams(organizationId?: string): Promise<Team[]> {
  return (await db()).listTeams(organizationId);
}

export async function getTeam(id: string): Promise<Team | undefined> {
  return (await db()).getTeam(id);
}

export async function insertScan(row: {
  id: string;
  organizationId?: string;
  teamId?: string;
  target: string;
  status: string;
}): Promise<void> {
  return (await db()).insertScan(row);
}

export async function updateScan(
  id: string,
  updates: { status: string; resultJson?: string; error?: string; completedAt?: string }
): Promise<void> {
  return (await db()).updateScan(id, updates);
}

export async function getScan(id: string): Promise<ScanRow | undefined> {
  return (await db()).getScan(id);
}

export async function listScans(options: {
  organizationId?: string;
  teamId?: string;
  limit?: number;
}): Promise<ScanRow[]> {
  return (await db()).listScans(options);
}
