import { defineHandler } from 'nitro';
import { db } from '../../../utils/core';
import {
  enforceTenantAccess,
  fail,
  param,
  parseResultJson,
  requireTenantHeaders,
} from '../../../utils/http';

/** GET /scan/:id - scan status/results */
export default defineHandler(async (event) => {
  requireTenantHeaders(event);
  const row = await db.getScan(param(event, 'id'));
  if (!row) fail(404, { error: 'Scan not found' });
  if (!enforceTenantAccess(event, row.organization_id, row.team_id)) {
    fail(403, { error: 'Forbidden' });
  }
  return {
    id: row.id,
    status: row.status,
    target: row.target,
    result: parseResultJson(row.result_json),
    error: row.error,
    createdAt: row.created_at,
    completedAt: row.completed_at,
  };
});
