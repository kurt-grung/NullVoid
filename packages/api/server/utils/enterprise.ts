import * as crypto from 'node:crypto';
import type { H3Event } from 'nitro/h3';
import { enterpriseTypes, newAuditId, store } from './core';
import { fail, header } from './http';
import type { RbacRole } from '../../src/enterprise/types';

export function getRole(event: H3Event): RbacRole {
  const h = header(event, 'x-nullvoid-role');
  if (h === 'admin' || h === 'analyst' || h === 'viewer') return h;
  return 'admin';
}

export function requireRole(event: H3Event, can: 'scan' | 'webhooks' | 'audit'): void {
  const role = getRole(event);
  const ok =
    can === 'scan'
      ? enterpriseTypes.roleCanTriggerScan(role)
      : can === 'webhooks'
        ? enterpriseTypes.roleCanManageWebhooks(role)
        : enterpriseTypes.roleCanViewAudit(role);
  if (!ok) fail(403, { error: 'Forbidden' });
}

export function orgHeader(event: H3Event): string | null {
  return header(event, 'x-organization-id') ?? null;
}

export function auditFromRequest(
  event: H3Event,
  action: Parameters<typeof store.appendAudit>[0]['action'],
  resourceType?: string,
  resourceId?: string,
  details?: Record<string, unknown>
): void {
  store.appendAudit({
    id: newAuditId(),
    organizationId: orgHeader(event),
    teamId: header(event, 'x-team-id') ?? null,
    actor: header(event, 'x-api-key') ? 'api-key' : 'anonymous',
    action,
    resourceType,
    resourceId,
    details,
    createdAt: new Date().toISOString(),
  });
}

export function webhookSecret(): string {
  return crypto.randomBytes(32).toString('hex');
}
