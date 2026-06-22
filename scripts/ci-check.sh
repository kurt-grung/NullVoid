#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

echo "==> build"
npm run build

echo "==> lint"
npm run lint

echo "==> type-check"
npm run type-check

echo "==> format:check"
npm run format:check

echo "==> verify unit test isolation"
bash .github/scripts/verify-unit-test-isolation.sh

echo "==> test"
npm test

echo "ci-check: all passed"
