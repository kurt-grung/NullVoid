import { defineHandler } from 'nitro';
import { store } from '../../utils/core';
import { auditFromRequest, requireRole } from '../../utils/enterprise';
import { fail, param } from '../../utils/http';

export default defineHandler((event) => {
  requireRole(event, 'webhooks');
  const id = param(event, 'id');
  if (!store.deleteWebhook(id)) fail(404, { error: 'Webhook not found' });
  auditFromRequest(event, 'webhook.deleted', 'webhook', id);
  return { ok: true };
});
