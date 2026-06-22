#!/usr/bin/env bash
set -euo pipefail

OWNER="${GITHUB_OWNER:-kurt-grung}"
REPO="${GITHUB_REPO:-NullVoid}"
PROJECT_TITLE="${PROJECT_TITLE:-NullVoid Advanced Roadmap}"
FIRST_ISSUE="${FIRST_ISSUE:-22}"
LAST_ISSUE="${LAST_ISSUE:-41}"
PROJECT_NUMBER="${PROJECT_NUMBER:-}"

if ! gh auth status >/dev/null 2>&1; then
  echo "Run: gh auth login"
  exit 1
fi

if ! gh project list --owner "$OWNER" >/dev/null 2>&1; then
  echo "Missing project scope. Run in your terminal (browser auth required):"
  echo "  gh auth refresh -h github.com -s project,read:project"
  exit 1
fi

resolve_project_number() {
  if [[ -n "$PROJECT_NUMBER" ]]; then
    echo "$PROJECT_NUMBER"
    return
  fi
  gh project list --owner "$OWNER" --format json \
    | jq -r --arg title "$PROJECT_TITLE" '.projects[] | select(.title == $title) | .number' \
    | head -1
}

PROJECT_NUMBER="$(resolve_project_number)"

if [[ -z "$PROJECT_NUMBER" ]]; then
  echo "Creating project: $PROJECT_TITLE"
  PROJECT_URL=$(gh project create --owner "$OWNER" --title "$PROJECT_TITLE" --format json | jq -r '.url')
  PROJECT_NUMBER=$(echo "$PROJECT_URL" | grep -oE '[0-9]+$')
  echo "Project: $PROJECT_URL (#${PROJECT_NUMBER})"
  echo "Linking repo ${OWNER}/${REPO}"
  gh project link "$PROJECT_NUMBER" --owner "$OWNER" --repo "$OWNER/$REPO"
else
  PROJECT_URL="https://github.com/users/${OWNER}/projects/${PROJECT_NUMBER}"
  echo "Using existing project: $PROJECT_URL (#${PROJECT_NUMBER})"
fi

echo "Adding roadmap epics (#${FIRST_ISSUE}-#${LAST_ISSUE})"
for n in $(seq "${FIRST_ISSUE}" "${LAST_ISSUE}"); do
  ISSUE_URL="https://github.com/${OWNER}/${REPO}/issues/${n}"
  echo "  + #${n}"
  gh project item-add "$PROJECT_NUMBER" --owner "$OWNER" --url "$ISSUE_URL" >/dev/null
done

echo ""
echo "Done. Open: ${PROJECT_URL}"
echo "Set columns in the UI: Backlog | Roadmap | In progress | In review | Done"
echo "Optional fields: Phase (0-5), Pillar, Exit criterion"
