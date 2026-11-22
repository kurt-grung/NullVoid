import { defineHandler } from 'nitro';
import { db } from '../../utils/core';
import { json, readJson } from '../../utils/http';

/** POST /organizations - create organization */
export default defineHandler(async (event) => {
  const body = await readJson(event);
  const org = await db.createOrganization((body['name'] as string) ?? 'Default');
  return json(event, 201, org);
});
