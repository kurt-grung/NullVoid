#!/usr/bin/env bash
set -euo pipefail

PR="${1:?usage: babysit-pr.sh <pr-number>}"
MAX_WAIT_MINUTES="${MAX_WAIT_MINUTES:-45}"
POLL_SECONDS="${POLL_SECONDS:-30}"

deadline=$((SECONDS + MAX_WAIT_MINUTES * 60))

echo "Watching PR #${PR} checks (max ${MAX_WAIT_MINUTES}m)..."

while (( SECONDS < deadline )); do
  if ! gh pr view "${PR}" --json state -q '.state' | grep -q OPEN; then
    state=$(gh pr view "${PR}" --json state,mergedAt -q '.state')
    if [[ "${state}" == "MERGED" ]]; then
      echo "PR #${PR} merged."
      exit 0
    fi
    echo "PR #${PR} is ${state} (not open)." >&2
    exit 1
  fi

  mapfile -t rows < <(gh pr checks "${PR}" --json name,state,bucket -q '.[] | [.name,.state,.bucket] | @tsv')

  pending=0
  failed=0
  for row in "${rows[@]}"; do
    IFS=$'\t' read -r name state bucket <<< "${row}"
    if [[ "${state}" == "FAILURE" || "${state}" == "ERROR" || "${bucket}" == "fail" ]]; then
      echo "FAIL: ${name} (${state})"
      failed=$((failed + 1))
    elif [[ "${state}" == "PENDING" || "${state}" == "IN_PROGRESS" || "${state}" == "QUEUED" || "${state}" == "WAITING" ]]; then
      pending=$((pending + 1))
    fi
  done

  if (( failed > 0 )); then
    echo "PR #${PR} has ${failed} failing check(s). Fix, push, and re-run babysit-pr.sh." >&2
    exit 2
  fi

  if (( pending == 0 )) && (( ${#rows[@]} > 0 )); then
    echo "All checks passed for PR #${PR}."
    exit 0
  fi

  echo "Waiting… (${pending} pending, ${#rows[@]} total checks)"
  sleep "${POLL_SECONDS}"
done

echo "Timed out waiting for PR #${PR} checks." >&2
exit 3
