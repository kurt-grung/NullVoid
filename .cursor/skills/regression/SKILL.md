---
name: regression
description: >-
  Runs NullVoid regression validation — CI parity, performance benchmarks, optional
  ML held-out eval, and baseline comparison. Use when the user invokes /regression,
  asks to check for regressions, validate before merge, or compare perf/ML metrics
  to baseline.
disable-model-invocation: true
---

# NullVoid Regression (/regression)

Validate no regressions before merge or after risky changes.

| Constant | Value |
|----------|-------|
| Repo | `kurt-grung/NullVoid` |
| Root | `/Users/kurtgrung/Desktop/NullVoid` (or your clone) |
| CI parity | `npm run ci:check` → `scripts/ci-check.sh` |
| Roadmap epic | [#26 Performance regression suite](https://github.com/kurt-grung/NullVoid/issues/26) |

Requires Node 20.x and `npm ci` when lockfile or deps changed.

## Modes

| User intent | Action |
|-------------|--------|
| `/regression` or "full regression" | Tier 1 + Tier 2; Tier 3 when Python ML deps available |
| `/regression quick` | Tier 1 only |
| `/regression perf` | Tier 2 only |
| `/regression ml` | Tier 3 only |
| `/regression compare` | Tier 3 + compare to latest CI `ml-eval-report` artifact |

Stop on first failing tier unless the user asked to run everything and report all failures.

## Tier 1 — CI parity (required)

```bash
cd "${ROOT}"
npm run ci:check
```

Covers: build, lint, type-check, format, unit-test isolation verify, `npm test` (unit + integration + performance via Jest projects).

Individual steps when isolating a failure:

```bash
npm run build
npm run lint
npm run type-check
npm run format:check
bash .github/scripts/verify-unit-test-isolation.sh
npm test
```

**Unit test rule:** tests under `ts/test/unit/` must not hit live IoC APIs — use mocks or `jest.spyOn(getIoCManager(), 'queryAll')`.

## Tier 2 — Performance

```bash
npm run test:performance
```

Benchmarks live in `ts/test/performance/` (scan time ceiling, future IoC batching / parallel worker gates per roadmap).

If dashboard files changed in the current branch or working tree:

```bash
npm run dashboard:build
```

## Tier 3 — ML held-out eval (optional, heavier)

Requires Python 3.11+ and `python3 -m pip install -r ml-model/requirements.txt`.

```bash
npm run ml:heldout-dependency
```

Behavioral held-out (when investigating behavioral ML changes):

```bash
npm run ml:split-train-val -- \
  --input ml-model/train-behavioral.jsonl \
  --train-out ml-model/.eval-cache/beh-train.jsonl \
  --val-out ml-model/.eval-cache/beh-val.jsonl \
  --val-fraction 0.2 --seed 42 \
  --time-val-newest --time-field exportedAt
npm run ml:train-behavioral -- --input ml-model/.eval-cache/beh-train.jsonl --output-dir ml-model/.eval-cache/beh
node ts/dist/bin/nullvoid.js eval-behavioral \
  --input ml-model/.eval-cache/beh-val.jsonl \
  --model ml-model/.eval-cache/beh/behavioral-model.pkl \
  --keys ml-model/.eval-cache/beh/behavioral-feature_keys.pkl --json
```

Skip Tier 3 when the change does not touch `ml-model/`, `ts/src/**/ml*`, or behavioral scoring — note the skip in the report.

## Compare to CI baseline (`/regression compare`)

1. Run Tier 3 locally; save JSON output.
2. Fetch latest green **Tests** workflow artifact:

```bash
RUN_ID=$(gh run list --repo kurt-grung/NullVoid --workflow=tests.yml --branch=main --status=success --limit 1 --json databaseId -q '.[0].databaseId')
mkdir -p /tmp/ml-baseline && gh run download "${RUN_ID}" --repo kurt-grung/NullVoid --name ml-eval-report --dir /tmp/ml-baseline
```

3. Compare `roc_auc`, `precision`, and `recall` for dependency and behavioral models. Flag regressions when a metric drops more than ~2 pp vs baseline (or any CI floor breach).

See `ml-model/README.md` — **Drift / regression tracking**.

## Report format

After the run, return a compact summary:

```markdown
## Regression report

| Tier | Status | Notes |
|------|--------|-------|
| CI parity | pass/fail | … |
| Performance | pass/fail/skip | duration if relevant |
| ML held-out | pass/fail/skip | key metrics |
| vs CI baseline | pass/fail/n/a | deltas |

### Failures
- <command>: <first error line or test name>

### Next steps
- <scoped fix or re-run command>
```

On failure: fix the root cause in scope, re-run the failed tier only, then re-run full `/regression` before merge.

## When to invoke

- Before opening or merging a PR (especially detection, API, dashboard, ML)
- After resolving merge conflicts or rebasing onto `main`
- After dependency bumps (`package-lock.json`, `ml-model/requirements.txt`)
- When investigating suspected perf or ML metric drift

## Optional — verifier subagent

After all tiers pass and the change is user-facing (dashboard, API contract, CLI output), launch the **verifier** subagent to smoke-test the implementation. Do not launch verifier on test-only or docs-only runs unless the user asks.

## Quick reference

```bash
npm run ci:check
npm run test:performance
npm run dashboard:build
npm run ml:heldout-dependency
gh run list --repo kurt-grung/NullVoid --workflow=tests.yml --limit 5
```
