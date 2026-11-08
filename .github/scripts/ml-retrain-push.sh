#!/usr/bin/env bash
set -euo pipefail

branch="${1:?usage: ml-retrain-push.sh <branch>}"
commit_subject="chore(ml): retrain dependency and behavioral models from GHSA [skip ci]"

retrain_files=(
  ml-model/train.jsonl
  ml-model/model.model.json
  ml-model/model.calib.json
  ml-model/metadata.json
  ml-model/train-behavioral.jsonl
  ml-model/behavioral.model.json
  ml-model/behavioral.calib.json
  ml-model/behavioral-metadata.json
)

git config user.name "github-actions[bot]"
git config user.email "github-actions[bot]@users.noreply.github.com"

staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT

for file in "${retrain_files[@]}"; do
  cp "$file" "$staging/$(basename "$file")"
done

for attempt in 1 2 3 4 5; do
  git fetch origin "$branch"
  git reset --hard "origin/$branch"

  for file in "${retrain_files[@]}"; do
    cp "$staging/$(basename "$file")" "$file"
  done

  git add "${retrain_files[@]}"
  if git diff --cached --quiet; then
    echo "Model artifacts match origin/${branch}; nothing to push."
    exit 0
  fi

  git commit -m "$commit_subject"

  if git push origin "HEAD:$branch"; then
    echo "Pushed model updates to ${branch}."
    exit 0
  fi

  echo "Push rejected (attempt ${attempt}/5), retrying..."
  sleep $((attempt * 2))
done

echo "Failed to push model updates after 5 attempts" >&2
exit 1
