#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKFLOW="${ROOT}/.github/workflows/security-scan.yml"

if [ ! -f "${WORKFLOW}" ]; then
  echo "security-scan parity: missing ${WORKFLOW}"
  exit 1
fi

count="$(grep -c -- '--no-dependency-source' "${WORKFLOW}" || true)"
if [ "${count}" -lt 2 ]; then
  echo "security-scan parity: expected --no-dependency-source on both NullVoid scan steps (found ${count})"
  exit 1
fi

REPORT="$(mktemp "${TMPDIR:-/tmp}/nv-self-scan.XXXXXX.json")"
trap 'rm -f "${REPORT}"' EXIT

node "${ROOT}/ts/dist/bin/nullvoid.js" "${ROOT}" \
  --format json \
  --output "${REPORT}" \
  --no-ioc \
  --no-dependency-source

CRITICAL="$(
  jq '[.threats[] | select(.severity == "CRITICAL" and .type != "VULNERABLE_PACKAGE")] | length' "${REPORT}"
)"
HIGH="$(
  jq '[.threats[] | select(.severity == "HIGH" and .type != "VULNERABLE_PACKAGE")] | length' "${REPORT}"
)"

if [ "${CRITICAL}" -gt 0 ] || [ "${HIGH}" -gt 0 ]; then
  echo "security-scan parity: self-scan would fail PR gate (critical=${CRITICAL}, high=${HIGH})"
  jq '[.threats[] | select(.severity == "CRITICAL" or .severity == "HIGH") | {type, severity, message, filePath}][0:10]' \
    "${REPORT}"
  exit 1
fi

echo "security-scan parity: ok"
