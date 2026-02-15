# NullVoid ML Model

Train and serve a small ML model for dependency confusion threat scoring.

## Quick Start

From the **project root**:

```bash
# 1. Install Python deps (one-time)
cd ml-model && pip3 install -r requirements.txt && cd ..

# 2. Export features (optional; train.jsonl may already exist)
npm run ml:export

# Or export from malware projects you've scanned (appends packages with threats as label 1):
nullvoid scan /path/to/malware-projects --train

# 3. Train the model
npm run ml:train

# 4. Start the ML server (keep running)
npm run ml:serve
```

Or run from `ml-model/` directly:

```bash
cd ml-model
pip3 install -r requirements.txt
node export-features.js --out train.jsonl
python3 train.py --input train.jsonl --output model.pkl
python3 serve.py --port 8000
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
