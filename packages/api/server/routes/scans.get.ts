import { defineHandler } from 'nitro';
import { db } from '../utils/core';
import { query, requireTenantHeaders } from '../utils/http';

/** GET /scans - list scans (filter by org/team) */
export default defineHandler(async (event) => {
  const { organizationId, teamId } = requireTenantHeaders(event);
  const parsedLimit = parseInt(query(event, 'limit') as string, 10);
  const limit = Number.isFinite(parsedLimit) ? Math.max(1, Math.min(parsedLimit, 100)) : 50;
  const parsedOffset = parseInt(query(event, 'offset') as string, 10);
  const offset = Number.isFinite(parsedOffset) ? Math.max(0, parsedOffset) : 0;
  const rows = await db.listScans({ organizationId, teamId, limit, offset });
  return {
    scans: rows.map((r) => ({
      id: r.id,
      status: r.status,
      target: r.target,
      organizationId: r.organization_id,
      teamId: r.team_id,
      createdAt: r.created_at,
      completedAt: r.completed_at,
    })),
  };
});
