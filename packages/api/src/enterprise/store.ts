import type { AuditEntry, ScheduleEntry, WebhookEntry } from './types';

const schedules: ScheduleEntry[] = [];
const webhooks: WebhookEntry[] = [];
const auditLog: AuditEntry[] = [];

export function listSchedules(orgId?: string | null): ScheduleEntry[] {
  return schedules.filter((s) => !orgId || s.organizationId === orgId);
}

export function createSchedule(entry: ScheduleEntry): ScheduleEntry {
  schedules.push(entry);
  return entry;
}

export function deleteSchedule(id: string): boolean {
  const idx = schedules.findIndex((s) => s.id === id);
  if (idx < 0) return false;
  schedules.splice(idx, 1);
  return true;
}

export function listWebhooks(orgId?: string | null): WebhookEntry[] {
  return webhooks.filter((w) => !orgId || w.organizationId === orgId);
}

export function createWebhook(entry: WebhookEntry): WebhookEntry {
  webhooks.push(entry);
  return entry;
}

export function deleteWebhook(id: string): boolean {
  const idx = webhooks.findIndex((w) => w.id === id);
  if (idx < 0) return false;
  webhooks.splice(idx, 1);
  return true;
}

export function appendAudit(entry: AuditEntry): void {
  auditLog.unshift(entry);
  if (auditLog.length > 5000) auditLog.length = 5000;
}

export function listAudit(orgId?: string | null, limit = 100): AuditEntry[] {
  const filtered = orgId ? auditLog.filter((e) => e.organizationId === orgId) : auditLog;
  return filtered.slice(0, limit);
}

export async function dispatchWebhooks(
  event: string,
  payload: Record<string, unknown>,
  orgId?: string | null
): Promise<void> {
  const crypto = await import('crypto');
  const targets = listWebhooks(orgId).filter(
    (w) => w.enabled && w.events.includes(event)
  );
  await Promise.all(
    targets.map(async (hook) => {
      const body = JSON.stringify({ event, payload, timestamp: new Date().toISOString() });
      const signature = crypto
        .createHmac('sha256', hook.secret)
        .update(body)
        .digest('hex');
      try {
        await fetch(hook.url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-NullVoid-Signature': signature,
          },
          body,
        });
      } catch {
        /* webhook delivery best-effort */
      }
    })
  );
}
