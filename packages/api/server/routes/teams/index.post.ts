import { defineHandler } from 'nitro';
import { db } from '../../utils/core';
import { fail, json, readJson } from '../../utils/http';

/** POST /teams - create team (requires organizationId in body) */
export default defineHandler(async (event) => {
  const body = await readJson(event);
  const organizationId = body['organizationId'] as string;
  const name = (body['name'] as string) ?? 'Default';
  if (!organizationId) fail(400, { error: 'organizationId required' });
  const org = await db.getOrganization(organizationId);
  if (!org) fail(404, { error: 'Organization not found' });
  return json(event, 201, await db.createTeam(organizationId, name));
});
