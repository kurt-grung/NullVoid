#!/usr/bin/env bash
set -euo pipefail

OWNER="${GITHUB_OWNER:-kurt-grung}"
REPO="${GITHUB_REPO:-NullVoid}"
PROJECT_TITLE="${PROJECT_TITLE:-NullVoid Advanced Roadmap}"
FIRST_ISSUE="${FIRST_ISSUE:-22}"
LAST_ISSUE="${LAST_ISSUE:-41}"

if ! gh auth status >/dev/null 2>&1; then
  echo "Run: gh auth login"
  exit 1
fi

if ! gh api graphql -f query='query{ viewer { login } }' >/dev/null 2>&1; then
  echo "GitHub CLI cannot call GraphQL. Refresh scopes:"
  echo "  gh auth refresh -h github.com -s project,read:project"
  exit 1
fi

SCOPE_CHECK=$(gh api user -q '.login' 2>/dev/null || true)
if ! gh project list --owner "$OWNER" >/dev/null 2>&1; then
  echo "Missing project scope. Run in your terminal (browser auth required):"
  echo "  gh auth refresh -h github.com -s project,read:project"
  exit 1
fi

echo "Creating project: $PROJECT_TITLE"
PROJECT_URL=$(gh project create --owner "$OWNER" --title "$PROJECT_TITLE" --format json | jq -r '.url')
PROJECT_NUMBER=$(echo "$PROJECT_URL" | grep -oE '[0-9]+$')
echo "Project: $PROJECT_URL (#$PROJECT_NUMBER)"

echo "Linking repo $OWNER/$REPO"
gh project link "$PROJECT_NUMBER" --owner "$OWNER" --repo "$OWNER/$REPO"

echo "Adding roadmap epics (#$FIRST_ISSUE–#$LAST_ISSUE)"
for n in $(seq "$FIRST_ISSUE" "$LAST_ISSUE"); do
  ISSUE_URL="https://github.com/$OWNER/$REPO/issues/$n"
  echo "  + #$n"
  gh project item-add "$PROJECT_NUMBER" --owner "$OWNER" --url "$ISSUE_URL" >/dev/null
done

echo ""
echo "Done. Open: $PROJECT_URL"
echo "Set columns in the UI: Backlog | Roadmap | In progress | In review | Done"
echo "Optional fields: Phase (0–5), Pillar, Exit criterion"
