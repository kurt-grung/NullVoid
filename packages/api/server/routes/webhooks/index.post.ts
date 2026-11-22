import { defineHandler } from 'nitro';
import { store } from '../../utils/core';
import { auditFromRequest, orgHeader, requireRole, webhookSecret } from '../../utils/enterprise';
import { fail, json, newId, readJson } from '../../utils/http';

export default defineHandler(async (event) => {
  requireRole(event, 'webhooks');
  const body = await readJson(event);
  const url = body['url'] as string | undefined;
  const events = body['events'] as string[] | undefined;
  if (!url || !Array.isArray(events) || events.length === 0) {
    fail(400, { error: 'url and events[] required' });
  }
  const secret = webhookSecret();
  const entry = store.createWebhook({
    id: newId('wh'),
    organizationId: orgHeader(event),
    url,
    secret,
    events,
    enabled: true,
    createdAt: new Date().toISOString(),
  });
  auditFromRequest(event, 'webhook.created', 'webhook', entry.id, { url, events });
  return json(event, 201, { ...entry, secret });
});
