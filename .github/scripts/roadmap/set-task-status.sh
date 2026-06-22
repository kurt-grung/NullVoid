#!/usr/bin/env bash
set -euo pipefail

OWNER="${GITHUB_OWNER:-kurt-grung}"
PROJECT_NUMBER="${PROJECT_NUMBER:-3}"
ISSUE_NUMBER="${1:?usage: set-task-status.sh <issue-number> <Todo|In Progress|Done>}"
STATUS_NAME="${2:?usage: set-task-status.sh <issue-number> <Todo|In Progress|Done>}"

FIELD_ID=$(gh project field-list "${PROJECT_NUMBER}" --owner "${OWNER}" --format json \
  | jq -r '.fields[] | select(.name=="Status") | .id')

OPTION_ID=$(gh project field-list "${PROJECT_NUMBER}" --owner "${OWNER}" --format json \
  | jq -r --arg s "${STATUS_NAME}" '.fields[] | select(.name=="Status") | .options[] | select(.name==$s) | .id')

ITEM_ID=$(gh project item-list "${PROJECT_NUMBER}" --owner "${OWNER}" --limit 100 --format json \
  | jq -r --argjson n "${ISSUE_NUMBER}" '.items[] | select(.content.number==$n) | .id' | head -1)

if [[ -z "${ITEM_ID}" || "${ITEM_ID}" == "null" ]]; then
  echo "error: issue #${ISSUE_NUMBER} not on project ${PROJECT_NUMBER}" >&2
  exit 1
fi

gh project item-edit "${PROJECT_NUMBER}" --owner "${OWNER}" --id "${ITEM_ID}" \
  --field-id "${FIELD_ID}" --single-select-option-id "${OPTION_ID}"

echo "Set #${ISSUE_NUMBER} → ${STATUS_NAME}"
