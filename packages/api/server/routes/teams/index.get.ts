import { defineHandler } from 'nitro';
import { API_KEY } from '../../utils/config';
import { db } from '../../utils/core';
import { query, requireTenantHeaders } from '../../utils/http';

/** GET /teams - list teams (optional ?organizationId=) */
export default defineHandler(async (event) => {
  let orgId = query(event, 'organizationId');
  if (API_KEY) {
    const tenant = requireTenantHeaders(event);
    orgId = tenant.organizationId ?? orgId;
  }
  return { teams: await db.listTeams(orgId) };
});
