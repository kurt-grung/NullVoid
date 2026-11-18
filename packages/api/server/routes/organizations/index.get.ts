import { defineHandler } from 'nitro';
import { API_KEY } from '../../utils/config';
import { db } from '../../utils/core';
import { requireTenantHeaders } from '../../utils/http';

/** GET /organizations - list organizations (scoped to the caller's org with API key auth) */
export default defineHandler(async (event) => {
  if (API_KEY) {
    const tenant = requireTenantHeaders(event);
    if (tenant.organizationId) {
      const org = await db.getOrganization(tenant.organizationId);
      return { organizations: org ? [org] : [] };
    }
  }
  return { organizations: await db.listOrganizations() };
});
