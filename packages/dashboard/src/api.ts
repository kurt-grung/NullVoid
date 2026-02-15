const API_BASE = import.meta.env.VITE_API_URL ?? '/api';

export interface ScanSummary {
  id: string;
  status: string;
  target: string;
  organizationId?: string;
  teamId?: string;
  createdAt: string;
  completedAt?: string;
}

export interface ScanDetail extends ScanSummary {
  result?: ScanResult;
  error?: string;
}

export interface ScanResult {
  threats: Threat[];
  summary: { totalFiles: number; totalPackages: number; threatsFound: number; scanDuration: number };
  riskAssessment?: { overall: number; byCategory: Record<string, number>; bySeverity: Record<string, number> };
  metadata?: Record<string, unknown>;
}

export interface Threat {
  type: string;
  message: string;
  severity: string;
  confidence?: number;
  package?: string;
  details?: string;
}

export interface Organization {
  id: string;
  name: string;
  created_at: string;
}

export interface Team {
  id: string;
  organization_id: string;
  name: string;
  created_at: string;
}

async function fetchApi<T>(path: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...opts?.headers },
    ...opts,
  });
  if (!res.ok) {
    const text = await res.text();
    const msg = text.startsWith('<') ? `API error ${res.status}: Ensure NullVoid API is running on port 3001` : text;
    throw new Error(msg);
  }
  return res.json();
}

export async function getScans(orgId?: string, teamId?: string): Promise<{ scans: ScanSummary[] }> {
  const headers: Record<string, string> = {};
  if (orgId) headers['X-Organization-Id'] = orgId;
  if (teamId) headers['X-Team-Id'] = teamId;
  return fetchApi(`/scans?limit=100`, { headers });
}

export async function getScan(id: string, orgId?: string, teamId?: string): Promise<ScanDetail> {
  const headers: Record<string, string> = {};
  if (orgId) headers['X-Organization-Id'] = orgId;
  if (teamId) headers['X-Team-Id'] = teamId;
  return fetchApi(`/scan/${id}`, { headers });
}

export async function triggerScan(target: string, orgId?: string, teamId?: string): Promise<{ id: string; status: string; target: string }> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (orgId) headers['X-Organization-Id'] = orgId;
  if (teamId) headers['X-Team-Id'] = teamId;
  const res = await fetch(`${API_BASE}/scan`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ target }),
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function getOrganizations(): Promise<{ organizations: Organization[] }> {
  return fetchApi('/organizations');
}

export async function getTeams(orgId?: string): Promise<{ teams: Team[] }> {
  return fetchApi(orgId ? `/teams?organizationId=${encodeURIComponent(orgId)}` : '/teams');
}
