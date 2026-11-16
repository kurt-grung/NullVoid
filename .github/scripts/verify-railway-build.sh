#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

echo "railway build smoke: api"
npm run api:build

echo "railway build smoke: dashboard"
VITE_BASE=/ npm run dashboard:build

test -f packages/api/dist/index.js
test -f packages/api/.output/server/index.mjs
test -f packages/dashboard/dist/index.html

echo "railway build smoke: ok"
