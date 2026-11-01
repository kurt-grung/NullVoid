#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

if [ -f Dockerfile ]; then
  echo "railway config: root Dockerfile must not exist (Railway auto-builds it for every service)"
  exit 1
fi

for f in docker/Dockerfile railway.json railway.dashboard.json .nvmrc; do
  if [ ! -f "${f}" ]; then
    echo "railway config: missing ${f}"
    exit 1
  fi
done

node -e "
const fs = require('fs');
const rootPkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
if (rootPkg.engines?.node !== '24.x') {
  console.error('railway config: package.json engines.node must be 24.x');
  process.exit(1);
}
if (!rootPkg.allowScripts?.['better-sqlite3']) {
  console.error('railway config: allowScripts must include better-sqlite3');
  process.exit(1);
}
for (const file of ['railway.json', 'railway.dashboard.json']) {
  const cfg = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (cfg.build?.builder !== 'RAILPACK') {
    console.error(\`railway config: \${file} must use RAILPACK builder\`);
    process.exit(1);
  }
}
"

echo "railway config: ok"
