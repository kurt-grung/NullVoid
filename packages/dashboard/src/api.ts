const API_BASE = import.meta.env.VITE_API_URL ?? '/api';

/** Detect when API is unavailable (404, CORS, network, 503 config) - show friendly empty state */
export function isApiUnavailableError(error: unknown): boolean {
  const msg = error instanceof Error ? error.message : String(error);
  return (
    msg.includes('API error') ||
    msg.includes('404') ||
    msg.includes('503') ||
    msg.includes('Failed to fetch') ||
    msg.includes('NetworkError') ||
    msg.includes('Ensure NullVoid API') ||
    msg.includes('Database not configured') ||
    msg.includes('TURSO_DATABASE_URL')
  );
}

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
    if (res.status === 503) {
      try {
        const j = JSON.parse(text) as { hint?: string; message?: string };
        throw new Error(j.hint ?? j.message ?? 'Database not configured.');
      } catch (e) {
        const msg =
          e instanceof Error && /TURSO|Vercel|Environment Variables/.test(e.message)
            ? e.message
            : 'Database not configured. Add TURSO_DATABASE_URL and TURSO_AUTH_TOKEN in Vercel → Settings → Environment Variables.';
        throw new Error(msg);
      }
    }
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
