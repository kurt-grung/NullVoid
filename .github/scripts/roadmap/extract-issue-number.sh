#!/usr/bin/env bash
set -euo pipefail

PR="${1:?usage: extract-issue-number.sh <pr-number-or-branch>}"

if [[ "${PR}" =~ ^feat/issue-([0-9]+)- ]]; then
  echo "${BASH_REMATCH[1]}"
  exit 0
fi

if [[ "${PR}" =~ ^[0-9]+$ ]]; then
  BODY=$(gh pr view "${PR}" --json body,headRefName -q '.body + "\n" + .headRefName')
else
  BODY=$(gh pr list --head "${PR}" --json body,headRefName -q '.[0].body + "\n" + .[0].headRefName' 2>/dev/null || true)
fi

if [[ "${BODY}" =~ feat/issue-([0-9]+)- ]]; then
  echo "${BASH_REMATCH[1]}"
  exit 0
fi

if [[ "${BODY}" =~ [Cc]loses[[:space:]]+#([0-9]+) ]]; then
  echo "${BASH_REMATCH[1]}"
  exit 0
fi

echo "error: could not extract issue number from PR ${PR}" >&2
exit 1
