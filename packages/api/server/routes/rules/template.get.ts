import { defineHandler } from 'nitro';
import { customRules } from '../../utils/core';
import { query } from '../../utils/http';

/** GET /rules/template - example rules file for YAML or JSON */
export default defineHandler((event) => {
  const format = query(event, 'format') === 'json' ? 'json' : 'yaml';
  event.res.headers.set(
    'content-type',
    `${format === 'json' ? 'application/json' : 'text/yaml'}; charset=utf-8`
  );
  return customRules.rulesTemplate(format);
});
