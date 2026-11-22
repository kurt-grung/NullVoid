import { defineHandler } from 'nitro';
import { store } from '../../utils/core';
import { auditFromRequest, requireRole } from '../../utils/enterprise';
import { fail, param } from '../../utils/http';

export default defineHandler((event) => {
  requireRole(event, 'scan');
  const id = param(event, 'id');
  if (!store.deleteSchedule(id)) fail(404, { error: 'Schedule not found' });
  auditFromRequest(event, 'schedule.deleted', 'schedule', id);
  return { ok: true };
});
