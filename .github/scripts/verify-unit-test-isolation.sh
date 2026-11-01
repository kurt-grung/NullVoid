#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UNIT_DIR="${ROOT}/ts/test/unit"
errors=0

for file in "${UNIT_DIR}"/*.test.ts; do
  [[ -f "${file}" ]] || continue
  rel="${file#${ROOT}/}"

  if ! grep -q 'queryIoCProviders(' "${file}"; then
    continue
  fi

  if grep -q "jest.spyOn(getIoCManager(), 'queryAll'" "${file}"; then
    continue
  fi

  if grep -Eq "queryIoCProviders\([^,)]+,\s*[^,)]+,\s*\[" "${file}"; then
    continue
  fi

  echo "error: ${rel} calls queryIoCProviders without an explicit provider list or queryAll mock" >&2
  errors=$((errors + 1))
done

if (( errors > 0 )); then
  echo "unit test isolation: ${errors} violation(s)" >&2
  exit 1
fi

echo "unit test isolation: ok"
