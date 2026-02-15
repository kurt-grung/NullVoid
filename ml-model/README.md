# NullVoid ML Model

Train and serve a small ML model for dependency confusion threat scoring.

**Run commands from the `ml-model` directory.** From project root: `cd ml-model` first.

## Quick Start

### 1. Export features

```bash
# Known-good packages (label 0) and known-bad (label 1)
node export-features.js --good lodash,react,express,axios --bad malicious-pkg --out train.jsonl
```

Or use defaults (known-good only; add --bad for malicious):

```bash
node export-features.js --out train.jsonl
```

### 2. Train

```bash
pip install -r requirements.txt
python train.py --input train.jsonl --output model.pkl
```

### 3. Serve

```bash
python serve.py --port 8000
```

### 4. Configure NullVoid

Set `ML_MODEL_URL` in `.nullvoidrc` or environment:

```json
{
  "DEPENDENCY_CONFUSION_CONFIG": {
    "ML_DETECTION": {
      "ML_MODEL_URL": "http://localhost:8000/score"
    }
  }
}
```

Or:

```bash
export NULLVOID_ML_MODEL_URL=http://localhost:8000/score
nullvoid scan .
```

## API contract

- **POST /score**
  - Request: `{"features": {"daysDifference": 30, "scopePrivate": 0, ...}}`
  - Response: `{"score": 0.42}` (0–1, higher = more suspicious)

## Feature schema

Features match `buildFeatureVector` output from `ts/src/lib/mlDetection.ts`:

- `daysDifference`, `recentCommitCount`, `scopePrivate`, `suspiciousPatternsCount`
- `timelineAnomaly`, `registryIsNpm`
- `authorCount`, `totalCommitCount`, `dominantAuthorShare`, `commitPatternAnomaly`
- `nlpSecurityScore`, `crossPackageAnomaly`, `behavioralAnomaly`
- `reviewSecurityScore`, `popularityScore`, `trustScore`
- etc.

## Custom data

For your own labeled data, produce JSONL with:

```json
{"features": {...}, "label": 0}
{"features": {...}, "label": 1}
```

Then run `python train.py --input your_data.jsonl`.
