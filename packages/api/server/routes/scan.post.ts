import { defineHandler } from 'nitro';
import { SCAN_ROOT } from '../utils/config';
import {
  customRules,
  db,
  getPackageMlRisk,
  getScanFn,
  newAuditId,
  scanTarget,
  store,
} from '../utils/core';
import { fail, json, readJson, requireTenantHeaders } from '../utils/http';
import { scanRateLimit } from '../utils/rateLimit';

/** POST /scan - run scan synchronously (required for serverless; no background jobs) */
export default defineHandler(async (event) => {
  scanRateLimit(event);
  const { organizationId, teamId } = requireTenantHeaders(event);
  const body = await readJson(event);

  let displayTarget: string;
  let resolvedTarget: string;
  try {
    ({ display: displayTarget, resolved: resolvedTarget } = scanTarget.sanitizeScanTarget(
      body['target'],
      SCAN_ROOT
    ));
  } catch (error) {
    fail(400, { error: (error as Error).message });
  }

  let scanRulesOptions: ReturnType<typeof customRules.buildScanRulesOptions> = {};
  try {
    scanRulesOptions = customRules.buildScanRulesOptions(
      {
        rulesFile: body['rulesFile'] as string | undefined,
        rules: body['rules'],
        mergeRulesWithDefaults: body['mergeRulesWithDefaults'] as boolean | undefined,
      },
      SCAN_ROOT
    );
  } catch (error) {
    fail(400, { error: (error as Error).message });
  }

  const id = `scan-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  const createdAt = new Date().toISOString();
  await db.insertScan({ id, organizationId, teamId, target: displayTarget, status: 'pending' });
  await db.updateScan(id, { status: 'running' });
  store.appendAudit({
    id: newAuditId(),
    organizationId,
    teamId,
    actor: 'api-key',
    action: 'scan.triggered',
    resourceType: 'scan',
    resourceId: id,
    details: { target: displayTarget },
    createdAt: new Date().toISOString(),
  });

  const packageSpecName = scanTarget.npmPackageNameOf(resolvedTarget);
  const scan = await getScanFn();
  try {
    const result = await scan(resolvedTarget, {
      depth: 5,
      ...scanRulesOptions,
      ...(body['mlThreats'] === true ? { mlThreats: true } : {}),
    });
    // Informational only: the model's view of an npm package's registry history.
    const mlRisk = packageSpecName ? await getPackageMlRisk(packageSpecName) : null;
    if (mlRisk && result && typeof result === 'object') {
      (result as Record<string, unknown>)['mlRisk'] = mlRisk;
    }
    const completedAt = new Date().toISOString();
    await db.updateScan(id, { status: 'completed', resultJson: JSON.stringify(result), completedAt });
    void store.dispatchWebhooks(
      'scan.completed',
      { scanId: id, target: displayTarget, status: 'completed' },
      organizationId
    );
    store.appendAudit({
      id: newAuditId(),
      organizationId,
      teamId,
      actor: 'api-key',
      action: 'scan.completed',
      resourceType: 'scan',
      resourceId: id,
      createdAt: completedAt,
    });
    return { id, status: 'completed', target: displayTarget, result, createdAt, completedAt };
  } catch (err) {
    const msg = (err as Error).message;
    const completedAt = new Date().toISOString();
    await db.updateScan(id, { status: 'failed', error: msg, completedAt });
    void store.dispatchWebhooks(
      'scan.failed',
      { scanId: id, target: displayTarget, status: 'failed', error: msg },
      organizationId
    );
    return json(event, 500, {
      id,
      status: 'failed',
      target: displayTarget,
      error: 'Scan execution failed',
      createdAt,
      completedAt,
    });
  }
});
