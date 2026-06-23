#!/usr/bin/env bash
set -euo pipefail

PR="${1:?usage: diagnose-ci-failure.sh <pr-number>}"

echo "==> Failing checks for PR #${PR}"
gh pr checks "${PR}" | grep -E 'fail|FAIL' || {
  echo "No failing checks."
  exit 0
}

run_id=$(gh pr view "${PR}" --json statusCheckRollup -q \
  '[.statusCheckRollup[] | select(.conclusion == "FAILURE" or .conclusion == "ERROR") | .detailsUrl] | .[0]' \
  | sed -n 's|.*/actions/runs/\([0-9]*\)/.*|\1|p')

if [[ -z "${run_id}" ]]; then
  echo "Could not resolve a failed workflow run id from PR checks."
  exit 1
fi

echo
echo "==> Failed log excerpt (run ${run_id})"
gh run view "${run_id}" --log-failed 2>/dev/null | tail -80 || gh run view "${run_id}" --log | tail -80

echo
echo "==> Reproduce locally (CI parity)"
echo "npm run ci:check"
