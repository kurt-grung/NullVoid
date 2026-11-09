'use strict';
const https = require('https');

function getJson(url, { headers = {}, timeout = 10000 } = {}) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { accept: 'application/json', ...headers } }, (res) => {
      if (res.statusCode < 200 || res.statusCode >= 300) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
      }
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c) => (body += c));
      res.on('end', () => {
        try {
          resolve(JSON.parse(body));
        } catch (e) {
          reject(e);
        }
      });
    });
    req.setTimeout(timeout, () => req.destroy(new Error('timeout')));
    req.on('error', reject);
  });
}
module.exports = { getJson };
