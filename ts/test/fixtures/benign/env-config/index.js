'use strict';
const fs = require('fs');
const path = require('path');

/** Load KEY=value lines from a .env file into an object (does not touch process.env). */
function parse(src) {
  const out = {};
  for (const raw of src.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    out[key] = value;
  }
  return out;
}
function load(file = path.join(process.cwd(), '.env')) {
  if (!fs.existsSync(file)) return {};
  return parse(fs.readFileSync(file, 'utf8'));
}
function required(config, keys) {
  const missing = keys.filter((k) => config[k] === undefined || config[k] === '');
  if (missing.length) throw new Error(`Missing config: ${missing.join(', ')}`);
  return config;
}
module.exports = { parse, load, required };
