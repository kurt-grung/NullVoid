#!/usr/bin/env bash
set -euo pipefail

API_URL="${NULLVOID_API_URL:-https://nullvoidapi-production.up.railway.app}"
HEALTH_URL="${API_URL%/}/health"

body="$(curl -sf --retry 8 --retry-delay 15 --retry-all-errors "${HEALTH_URL}?platform=1")"
ok="$(echo "${body}" | jq -r '.ok // empty')"
platform="$(echo "${body}" | jq -r '.platform // empty')"

if [ "${ok}" != "true" ]; then
  echo "production smoke: ${HEALTH_URL} did not return ok:true (${body})"
  exit 1
fi

if [ "${platform}" != "railway" ]; then
  echo "production smoke: expected platform=railway, got ${platform} (${body})"
  exit 1
fi

echo "production smoke: ok (${HEALTH_URL})"
