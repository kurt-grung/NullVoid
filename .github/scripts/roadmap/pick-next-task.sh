#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TASKS=$("${SCRIPT_DIR}/list-open-tasks.sh")

echo "${TASKS}" | jq '
  sort_by(
    if .status == "In Progress" then 0 else 1 end,
    .phase,
    .number
  )
  | .[0] // empty
'
