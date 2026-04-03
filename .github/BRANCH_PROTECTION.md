# Branch protection and required PR checks

CI workflows live under [`.github/workflows/`](workflows/). GitHub does **not** read branch rules from a file in the repo—you turn on **required status checks** in the repository settings.

## Checks that run on pull requests

| Workflow | Targets | Purpose |
|----------|---------|---------|
| **Tests** | PRs to `main` / `master` | `quality` job: build, lint, type-check, Prettier; `test` job: JS/TS tests + ML train/eval |
| **NullVoid Security Scan** | PRs to `main` | Build, NullVoid scan, SARIF, PR comment |

The **ML Model Retrain** workflow runs on push to `main` / `feat/ml-pipeline` and on a schedule—it is **not** a PR check.

## Enable required checks for `main`

1. Open the repo on GitHub → **Settings** → **Rules** → **Rulesets** (or **Branches** → **Branch protection rules**, depending on your UI).
2. Add a rule for branch **`main`** (or use the default branch name you use).
3. Enable **Require a pull request before merging** (optional but recommended).
4. Under **Require status checks to pass**, add checks **after at least one run** has completed so their names appear in the search list.

Typical check names (exact strings may include matrix labels—pick what GitHub shows):

- `Tests / quality`
- `Tests / test (20.x)` — if the job uses a matrix, the name includes the matrix value.
- `NullVoid Security Scan / security-scan`

5. Save the ruleset.

If a check name does not appear, open **Actions**, run the workflow once on a PR, then return to branch rules and search again.

## Local parity before pushing

```bash
npm ci
npm run build
npm run lint
npm run type-check
npm run format:check
npm test
```
