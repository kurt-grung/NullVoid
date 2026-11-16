import { defineHandler } from 'nitro';
import { customRules } from '../../utils/core';
import { json, readJson } from '../../utils/http';

/** POST /rules/validate - validate custom detection rules (JSON body) */
export default defineHandler(async (event) => {
  const body = await readJson(event);
  const result = customRules.validateRulesPayload(body?.['rules'] ?? body);
  if (result.valid) return { valid: true, errors: [] };
  return json(event, 400, { valid: false, errors: result.errors });
});
