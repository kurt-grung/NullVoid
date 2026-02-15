# NullVoid ML Model

Train and serve an XGBoost model for dependency confusion threat scoring. Supports calibration, explainability, batch scoring, and model versioning.

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

# 4. Start the ML server (keep running)
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
      "ML_EXPLAIN": true
    }
  }
}
```

## Export Features

```bash
# Known-good packages (label 0)
node export-features.js --good lodash,react,express --out train.jsonl

# Known-bad packages (label 1)
node export-features.js --bad package1,package2 --out train.jsonl

# Fetch npm packages from GitHub Security Advisories (label 1)
node export-features.js --from-ghsa --limit 200 --out train.jsonl

# Use GITHUB_TOKEN for higher API rate limits
GITHUB_TOKEN=ghp_xxx node export-features.js --from-ghsa --limit 500 --out train.jsonl
```

## Training Options

```bash
python train.py --input train.jsonl --output model.pkl
python train.py --input train.jsonl --balance          # Oversample minority class
python train.py --input train.jsonl --no-calibrate    # Skip Platt scaling
python train.py --input train.jsonl --output-dir models/v1  # Save to directory
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/score` | POST | Score a single feature vector. Add `"explain": true` for reasons and importance |
| `/batch-score` | POST | Score multiple feature vectors. Body: `{"features_list": [...], "explain": false}` |
| `/importance` | GET | Global feature importance from the model |
| `/model-info` | GET | Model metadata, version, training date |
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

## Serving Options

```bash
python serve.py --port 8000
python serve.py --model model.pkl --port 8000
python serve.py --model-dir models/v1 --port 8000
```

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

For per-sample SHAP explanations on `POST /explain`, install:

```bash
pip install shap
```

SHAP adds ~50MB; the server falls back to feature importance when SHAP is not installed.
