import { defineHandler } from 'nitro';
import { db } from '../../utils/core';
import { fail, param } from '../../utils/http';

/** GET /organizations/:id - get organization */
export default defineHandler(async (event) => {
  const org = await db.getOrganization(param(event, 'id'));
  if (!org) fail(404, { error: 'Organization not found' });
  return org;
});
