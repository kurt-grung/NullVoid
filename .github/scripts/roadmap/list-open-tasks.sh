#!/usr/bin/env bash
set -euo pipefail

OWNER="${GITHUB_OWNER:-kurt-grung}"
PROJECT_NUMBER="${PROJECT_NUMBER:-3}"
REPO="${GITHUB_REPO:-kurt-grung/NullVoid}"

if ! gh project list --owner "$OWNER" >/dev/null 2>&1; then
  echo "error: missing gh project scope. Run: gh auth refresh -h github.com -s project,read:project" >&2
  exit 1
fi

RAW=$(gh project item-list "${PROJECT_NUMBER}" --owner "${OWNER}" --limit 100 --format json)

echo "${RAW}" | jq --arg repo "${REPO}" '
  .items
  | map(select(
      .status != "Done"
      and (.content.type == "Issue" or .content.type == "DraftIssue")
      and (.repository | endswith($repo) or .content.repository == $repo)
    ))
  | map({
      number: .content.number,
      title: .title,
      status: .status,
      labels: .labels,
      url: .content.url,
      phase: ([.labels[] | select(startswith("phase:"))] | first // "unknown")
    })
  | sort_by(.phase, .number)
'
