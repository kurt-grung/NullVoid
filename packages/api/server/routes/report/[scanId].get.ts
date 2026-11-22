import { defineHandler } from 'nitro';
import { db, getReporting } from '../../utils/core';
import {
  enforceTenantAccess,
  fail,
  param,
  parseResultJson,
  query,
  requireTenantHeaders,
} from '../../utils/http';

/** GET /report/:scanId - HTML or Markdown report (?format=html|markdown&compliance=soc2|iso27001) */
export default defineHandler(async (event) => {
  requireTenantHeaders(event);
  const row = await db.getScan(param(event, 'scanId'));
  if (!row) fail(404, { error: 'Scan not found' });
  if (!enforceTenantAccess(event, row.organization_id, row.team_id)) {
    fail(403, { error: 'Forbidden' });
  }
  const result = parseResultJson(row.result_json);
  if (row.result_json && !result) fail(500, { error: 'Stored scan result is invalid JSON' });
  if (!result || row.status !== 'completed') {
    fail(400, { error: 'Scan not completed or no result' });
  }
  if (!result.metadata) result.metadata = {};
  const meta = result.metadata as Record<string, unknown>;
  meta['target'] = meta['target'] ?? row.target;

  const format = query(event, 'format') || 'html';
  const compliance = query(event, 'compliance') as 'soc2' | 'iso27001' | undefined;
  const opts = compliance ? { compliance } : undefined;
  const reporting = await getReporting();

  if (format === 'markdown') {
    event.res.headers.set('Content-Type', 'text/markdown; charset=utf-8');
    event.res.headers.set(
      'Content-Disposition',
      `attachment; filename="nullvoid-${String(row.target).replace(/[^a-zA-Z0-9.-]/g, '_')}-report.md"`
    );
    return reporting.generateMarkdownReport(result, opts);
  }
  event.res.headers.set('Content-Type', 'text/html; charset=utf-8');
  return reporting.generateHtmlReport(result, opts);
});
