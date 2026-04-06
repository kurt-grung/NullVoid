# NullVoid ML Model

Train and serve an XGBoost model for dependency confusion threat scoring. Supports calibration, explainability, batch scoring, and model versioning.

**Python:** 3.9+ is supported. GitHub Actions uses **3.11** for the ML train/eval step—use 3.11+ locally if you want the same `scikit-learn` resolution as CI.

## Quick Start

From the **project root**:

```bash
# 1. Install Python deps (one-time)
cd ml-model && pip3 install -r requirements.txt && cd ..

# 2. Export features (optional; train.jsonl may already exist)
npm run ml:export

# Or export known-bad packages from GitHub Security Advisories:
node ml-model/export-features.js --from-ghsa --limit 100 --out ml-model/train.jsonl

# Or export from malware projects you've scanned (appends packages with threats as label 1):
nullvoid scan /path/to/malware-projects --train

# For balanced training, also export clean packages (label 0):
nullvoid scan . --export-training ml-model/train.jsonl --export-training-good ml-model/train.jsonl

# 3. Train the model
npm run ml:train

# 4. (Optional) Evaluate metrics on train.jsonl with the saved model.pkl
npm run ml:eval

# Behavioral model (npm scripts / install hooks) — same idea:
npm run ml:export-behavioral
npm run ml:train-behavioral
npm run ml:eval-behavioral

# 5. Start the ML server (keep running)
npm run ml:serve
```

Or run from `ml-model/` directly:

```bash
cd ml-model
pip3 install -r requirements.txt
node export-features.js --from-ghsa --out train.jsonl
node export-features.js --good lodash,react --out train.jsonl
python3 train.py --input train.jsonl --balance --calibrate
python3 serve.py --port 8000
```

### Configure NullVoid

Set `ML_MODEL_URL` in `.nullvoidrc` or environment:

```json
{
  "DEPENDENCY_CONFUSION_CONFIG": {
    "ML_DETECTION": {
      "ML_MODEL_URL": "http://localhost:8000/score",
      "BEHAVIORAL_MODEL_URL": "http://localhost:8000/behavioral-score",
      "ML_EXPLAIN": true
    }
  }
}
```

Start the server with both weights loaded:

```bash
python3 serve.py --port 8000 --behavioral-model-dir .
```

## Behavioral training data

Behavioral features are built from **npm registry metadata** (scripts block, dependency counts, simple regex signals). Labels:

- **0 (good)**: pass `--good pkg1,pkg2,...` (defaults include common OSS packages).
- **1 (bad)**: `--from-ghsa` (npm packages linked to GitHub Security Advisories) and/or `--bad pkg1,pkg2`.

By default, `export-behavioral-features.js` **merges** into the output file if it already exists. For a clean file (e.g. scheduled retrain in CI), use **`--overwrite`**.

```bash
# Merge into train-behavioral.jsonl (typical local workflow)
node ml-model/export-behavioral-features.js --from-ghsa --limit 200 --out ml-model/train-behavioral.jsonl

# Replace file entirely (CI / reproducible snapshot)
node ml-model/export-behavioral-features.js --overwrite --from-ghsa --limit 200 \
  --good lodash,react,express,axios,chalk,typescript,jest,webpack,vue,next \
  --out ml-model/train-behavioral.jsonl

node ml-model/dedup-train.js ml-model/train-behavioral.jsonl ml-model/train-behavioral.jsonl
python3 ml-model/train-behavioral.py --input ml-model/train-behavioral.jsonl --balance --calibrate
```

This mirrors the dependency pipeline: **export → dedup → train**. The weekly **ML Model Retrain** workflow refreshes both `train.jsonl` and `train-behavioral.jsonl` from GHSA plus the same known-good list, then commits updated `model.pkl` and `behavioral-model.pkl` artifacts when they change.

## Export Features

Default export uses **npm registry metadata** plus the same **`buildFeatureVector`** path as the scanner when `ts/dist/lib` or `js/lib` is available (run `npm run build` from the repo root if `ts/dist` is missing). Rows include **`exportedAt`** (ISO-8601) for time-based splits.

```bash
# Known-good packages (label 0)
node export-features.js --good lodash,react,express --out train.jsonl

# Known-bad packages (label 1)
node export-features.js --bad package1,package2 --out train.jsonl

# Extra label lists: one package per line, # comments allowed
node export-features.js --good-file ./curated-good.txt --bad-file ./curated-bad.txt --out train.jsonl

# Fetch npm packages from GitHub Security Advisories (label 1)
node export-features.js --from-ghsa --limit 200 --out train.jsonl

# Use GITHUB_TOKEN for higher API rate limits
GITHUB_TOKEN=ghp_xxx node export-features.js --from-ghsa --limit 500 --out train.jsonl
```

### Git-enriched export (`--with-git`)

To match **commit / timeline** features from real scans, clone packages locally and point the exporter at those directories. Without a path, `--with-git` only warns and rows stay npm-only.

- **`--package-root <dir>`** — each package resolves to `<dir>/<scope>/<name>` for scoped names (e.g. `lodash` → `<dir>/lodash`, `@types/node` → `<dir>/@types/node`).
- **`--package-map <file.json>`** — object map `{ "package-name": "/absolute/or/relative/path" }` (overrides `--package-root` when both apply).

```bash
npm run build   # recommended so export uses ts/dist (same code as the scanner)

node export-features.js --good lodash,react --with-git --package-root ~/clones --out train.jsonl

# Example map
echo '{"lodash":"/path/to/lodash-clone","@scope/mypkg":"/path/to/mypkg"}' > paths.json
node export-features.js --good lodash,@scope/mypkg --with-git --package-map paths.json --out train.jsonl
```

**More label sources:** combine `--bad-file` with community-maintained malicious package lists (e.g. OpenSSF malicious-packages CSV converted to one npm name per line). Curate and version those files; dedup with `dedup-train.js` before training.

## Deduplication

When combining data from multiple sources (export-features, scan), deduplicate before training:

```bash
npm run ml:dedup
# or: node ml-model/dedup-train.js [input.jsonl] [output.jsonl]
```

The same script works for behavioral JSONL (used after `--overwrite` exports in CI).

## Offline evaluation and held-out validation

**In-sample** (quick check on the same file you trained on):

```bash
cd ml-model && python3 evaluate.py --input train.jsonl --model model.pkl --json
cd ml-model && python3 evaluate.py --behavioral --input train-behavioral.jsonl --model behavioral-model.pkl --json
```

**Held-out** validation (matches CI): split first, train only on the train split, then evaluate on the validation split:

```bash
python3 ml-model/split_train_val.py \
  --input ml-model/train.jsonl \
  --train-out /tmp/ml-train.jsonl \
  --val-out /tmp/ml-val.jsonl \
  --val-fraction 0.2 --seed 42
cd ml-model && python3 train.py --input /tmp/ml-train.jsonl --output /tmp/m.pkl --balance --calibrate
cd ml-model && python3 evaluate.py --input /tmp/ml-val.jsonl --model /tmp/m.pkl --keys /tmp/feature_keys.pkl --json --eval-set validation
```

**Time-based holdout** (when every JSONL row includes an ISO `exportedAt` from export scripts): oldest rows train, newest `val_fraction` validate—reduces temporal leakage. If any row is missing the field, the tool falls back to stratified splitting and prints a short JSON message on stderr.

```bash
python3 ml-model/split_train_val.py \
  --input ml-model/train.jsonl \
  --train-out /tmp/ml-train.jsonl \
  --val-out /tmp/ml-val.jsonl \
  --val-fraction 0.2 --seed 42 \
  --time-val-newest --time-field exportedAt
```

Optional **quality gates** (process exits with code 1 if the metric is computed and below the floor):

```bash
python3 evaluate.py --input /tmp/ml-val.jsonl --model /tmp/m.pkl --keys /tmp/feature_keys.pkl --min-roc-auc 0.55 --json
```

On every push to `main`, **Tests** uploads **`ml-eval-report.json`** (dependency + behavioral metrics on the held-out slice) and fails the job if held-out precision/recall (and behavioral ROC-AUC when defined) fall below conservative floors.

**Drift / regression tracking:** Download the `ml-eval-report` artifact from workflow runs and compare `roc_auc`, `precision`, and `recall` to a baseline commit when investigating dependency or data changes.

**One-shot held-out pipeline (from repo root):** writes splits under `ml-model/.eval-cache/` (gitignored), trains only on the train split, then prints validation JSON:

```bash
npm run ml:heldout-dependency
```

This runs `split_train_val.py` with **`--time-val-newest --time-field exportedAt`** when every row has `exportedAt`; otherwise it falls back to stratified splitting (see stderr JSON from the splitter). Use `ml:split-train-val`, `ml:train-heldout-cache`, and `ml:eval-heldout-cache` separately if you want to inspect intermediate files.

## Training Options

```bash
python train.py --input train.jsonl --output model.pkl
python train.py --input train.jsonl --balance          # Oversample minority class
python train.py --input train.jsonl --balance-class-weight  # Imbalance via XGBoost scale_pos_weight only (no oversampling)
python train.py --input train.jsonl --no-calibrate    # Skip Platt scaling
python train.py --input train.jsonl --output-dir models/v1  # Save to directory
```

Use **only one** of `--balance` or `--balance-class-weight`. After oversampling, `scale_pos_weight` is derived from the **post-balance** class counts (≈1.0 when classes match), which avoids double-weighting the minority class.

**Pinned XGBoost hyperparameters** live in `train.py` / `train-behavioral.py` as `XGBOOST_PARAMS` (`n_estimators`, `max_depth`, `learning_rate`, `subsample`, `colsample_bytree`, `min_child_weight`, …). The values used for a run are also written into `metadata.json` / `behavioral-metadata.json` under `xgboost_params` and `scale_pos_weight`.

**CI vs weekly retrain:** The scheduled **ML Model Retrain** workflow trains on the full deduplicated JSONL for maximum data; **Tests** retrains on a held-out split to measure generalization. Both are intentional.

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/score` | POST | Score a single feature vector. Add `"explain": true` for reasons and importance |
| `/batch-score` | POST | Score multiple feature vectors. Body: `{"features_list": [...], "explain": false}` |
| `/importance` | GET | Global feature importance from the model |
| `/model-info` | GET | Dependency + behavioral metadata, `feature_schema_version`, manifest `version` from `feature-keys.json` |
| `/explain` | GET | Same as `/importance` |
| `/explain` | POST | Per-sample explanation (SHAP when available) |
| `/health` | GET | Check if model is loaded |

### POST /score

Request:
```json
{"features": {"daysDifference": 30, "scopePrivate": 0, ...}, "explain": false}
```

Response:
```json
{"score": 0.42}
```

With `"explain": true`:
```json
{
  "score": 0.42,
  "reasons": ["timelineAnomaly=0.35: Package created very recently relative to repo history"],
  "importance": {"timelineAnomaly": 0.4, "scopePrivate": 0.15, ...}
}
```

### POST /batch-score

Request:
```json
{"features_list": [{"daysDifference": 30, ...}, {"daysDifference": 365, ...}], "explain": false}
```

Response:
```json
{"scores": [0.42, 0.12]}
```

`/batch-score` rejects requests larger than **`NULLVOID_ML_MAX_BATCH`** items (default **512**). Override the env var to raise the cap.

## Serving Options

```bash
python serve.py --port 8000
python serve.py --model model.pkl --port 8000
python serve.py --model-dir models/v1 --port 8000
```

## Feature manifest and known-good list

- **`feature-keys.json`** — canonical ordered `dependency` and `behavioral` feature names for `train.py`, `train-behavioral.py`, `serve.py`, and `ts/src/lib/mlFeatureKeys.ts`. Bump `version` when you add or reorder columns.
- **`training-defaults.json`** — `knownGoodPackages` used by `export-features.js` and `export-behavioral-features.js` when you omit `--good`, and by the weekly retrain workflow (no inline list).

### Extending the dependency feature schema

When you add or reorder columns (e.g. new NLP or code-quality signals in `buildFeatureVector`):

1. Update **`feature-keys.json`**: append or reorder keys and increment **`version`**.
2. **`ts/src/lib/mlFeatureKeys.ts`** imports that manifest at compile time—no manual list to edit unless you change how it is loaded.
3. Update **`export-features.js`** and **`ts/src/lib/mlDetection.ts`** (`buildFeatureVector`) so training rows and the scanner expose every key.
4. Run **`npm run test:ts`** and ensure **`ts/test/unit/ml-feature-parity.test.ts`** passes.
5. Retrain and bump committed **`model.pkl`** / metadata when you ship the new schema.

## Feature Schema

Features match `buildFeatureVector` output from `ts/src/lib/mlDetection.ts`:

- `daysDifference`, `recentCommitCount`, `scopePrivate`, `suspiciousPatternsCount`
- `timelineAnomaly`, `registryIsNpm`
- `authorCount`, `totalCommitCount`, `dominantAuthorShare`, `commitPatternAnomaly`
- `nlpSecurityScore`, `crossPackageAnomaly`, `behavioralAnomaly`
- `reviewSecurityScore`, `popularityScore`, `trustScore`
- etc.

## Requirements

- **macOS**: XGBoost requires OpenMP. Run `brew install libomp` if you see `Library not loaded: libomp.dylib`.

## Optional: SHAP

For TreeExplainer-based per-sample explanations on `POST /explain`, install optional deps on the **same environment that runs `serve.py`**:

```bash
pip install -r ml-model/requirements-optional.txt
```

SHAP adds a large dependency; the server still starts without it and uses feature-importance fallback. **`GET /health`** includes **`"shap": true|false`** so clients (e.g. the dashboard via `ML_SERVICE_URL`) can show whether the deployed scorer has SHAP enabled.
