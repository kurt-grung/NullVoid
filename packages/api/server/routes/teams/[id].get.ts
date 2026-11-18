import { defineHandler } from 'nitro';
import { db } from '../../utils/core';
import { fail, param } from '../../utils/http';

/** GET /teams/:id - get team */
export default defineHandler(async (event) => {
  const team = await db.getTeam(param(event, 'id'));
  if (!team) fail(404, { error: 'Team not found' });
  return team;
});
