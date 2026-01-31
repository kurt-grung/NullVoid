#!/usr/bin/env bash
# Run NullVoid and print a short summary (for use from Vim :! or terminal).
# Usage: ./scripts/nullvoid-vim.sh [directory]   (default: current dir)
# Uses temp file so output is always pure JSON (CLI sends progress to stderr for json format).
set -e
cd "${1:-.}"
tmp=$(mktemp 2>/dev/null || echo /tmp/nullvoid-vim-$$.json)
# Prefer local CLI: JS uses "scan . --output json"; TS uses " . -f json"
if [ -f "js/bin/nullvoid.js" ]; then
  node js/bin/nullvoid.js scan . --output json > "$tmp" 2>/dev/null || true
elif [ -f "ts/dist/bin/nullvoid.js" ]; then
  node ts/dist/bin/nullvoid.js . -f json > "$tmp" 2>/dev/null || true
else
  npx nullvoid scan . --output json > "$tmp" 2>/dev/null || true
fi
node -e "
const fs = require('fs');
try {
  const d = fs.readFileSync(process.argv[1], 'utf8');
  const j = JSON.parse(d);
  const n = (j.threats || []).length;
  console.log(n === 0 ? 'NullVoid: 0 issues' : 'NullVoid: ' + n + ' issue(s)');
  (j.threats || []).slice(0, 5).forEach((t, i) => console.log((i + 1) + '. ' + (t.type || '') + ' - ' + (t.message || '')));
} catch (e) {
  console.log('NullVoid: scan failed or no JSON output');
}
" "$tmp"
rm -f "$tmp"
