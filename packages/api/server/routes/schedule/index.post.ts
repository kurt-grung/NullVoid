import { defineHandler } from 'nitro';
import { store } from '../../utils/core';
import { auditFromRequest, orgHeader, requireRole } from '../../utils/enterprise';
import { fail, header, json, newId, readJson } from '../../utils/http';

export default defineHandler(async (event) => {
  requireRole(event, 'scan');
  const body = await readJson(event);
  const target = body['target'] as string | undefined;
  const cronExpression = body['cronExpression'] as string | undefined;
  if (!target || !cronExpression) fail(400, { error: 'target and cronExpression required' });
  const entry = store.createSchedule({
    id: newId('sched'),
    organizationId: orgHeader(event),
    teamId: header(event, 'x-team-id') ?? null,
    target,
    cronExpression,
    enabled: true,
    nextRunAt: null,
    createdAt: new Date().toISOString(),
  });
  auditFromRequest(event, 'schedule.created', 'schedule', entry.id, { target, cronExpression });
  return json(event, 201, entry);
});
