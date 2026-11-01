# PR: feat/ml-model – ML Detection & Advanced ML Pipeline

## Summary

Adds ML-powered dependency confusion detection and a full ML training pipeline to NullVoid. Includes TypeScript ML modules, subdir package scanning, GHSA auto-labeling, XGBoost model with calibration, explainability, and balanced training.

## Changes

### ML Detection (TypeScript)

- **Timeline analysis** (`ts/src/lib/timelineAnalysis.ts`): Git vs registry creation date comparison, anomaly scoring
- **Commit pattern analysis** (`ts/src/lib/commitPatternAnalysis.ts`): Author distribution, activity patterns, anomaly scoring
- **ML detection** (`ts/src/lib/mlDetection.ts`): Feature vector building, rule-based scoring, optional external model API
- **Config**: `.nullvoidrc` loading for `depth`, `defaultTarget`, `DEPENDENCY_CONFUSION_CONFIG`
- **Scan**: Scans all `package.json` subdirs; runs dependency confusion + ML per package
- **IoC cap**: Max 30 IoC queries per scan to avoid rate limits
- **Exclusions**: `ml-model/` excluded from malicious code detection

### ML Training Pipeline (`ml-model/`)

| Component | Description |
|-----------|-------------|
| `export-features.js` | Export feature vectors; `--good`/`--bad`, `--from-ghsa` (GitHub Security Advisories), full 21-feature export |
| `train.py` | XGBoost model, Platt calibration, `--balance` for class balancing, `metadata.json` |
| `serve.py` | FastAPI: `POST /score`, `POST /batch-score`, `GET /importance`, `GET /model-info`, `POST /explain` |
| `requirements.txt` | scikit-learn, joblib, xgboost, fastapi, uvicorn |

### Scan Enhancements

- **`--export-training <file>`**: Append feature vectors for packages with threats (label 1)
- **`--export-training-good <file>`**: Append feature vectors for packages with no threats (label 0) for balanced training
- **`--train`**: Shorthand for `--export-training ml-model/train.jsonl`
- **CODE_THREAT_TYPES**: Extended with `DEPENDENCY_CONFUSION_TIMELINE`, `DEPENDENCY_CONFUSION_SCOPE`, `DEPENDENCY_CONFUSION_ACTIVITY`, `DEPENDENCY_CONFUSION_PREDICTIVE_RISK`

### Explainability

- **ML_EXPLAIN** config: When enabled, API returns `reasons` and `importance` with scores
- **Human-readable reasons**: Feature-to-reason mapping (e.g. timelineAnomaly → "Package created very recently relative to repo history")
- **Optional SHAP**: `POST /explain` uses SHAP when installed for per-sample explanations

### Fixes & CI

- **Progress callback**: Skip non-file progress updates to avoid reading invalid paths
- **CI**: `--no-ioc` in security-scan workflow; minimal report on scan failure when `--output` is set
- **json-to-sarif**: Hardened error handling for non-Error exceptions

### npm Scripts

```json
"ml:serve": "cd ml-model && python3 serve.py --port 8000",
"ml:train": "cd ml-model && python3 train.py --input train.jsonl --output model.pkl",
"ml:export": "cd ml-model && node export-features.js --out train.jsonl",
"ml:scan": "node ts/dist/bin/nullvoid.js scan"
```

## Usage

```bash
# Export training data
npm run ml:export
node ml-model/export-features.js --from-ghsa --limit 100 --out ml-model/train.jsonl
nullvoid scan /path/to/malware --no-ioc --train
nullvoid scan . --export-training ml-model/train.jsonl --export-training-good ml-model/train.jsonl

# Train and serve
npm run ml:train
npm run ml:serve
```

Configure ML model URL in `.nullvoidrc`:

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

## Testing

- 376 tests across 43 test suites (199 JS + 177 TS)
- New: `ml-detection.test.ts`, `timeline-analysis.test.ts`, `commit-pattern-analysis.test.ts`

## Breaking Changes

None. All changes are additive. Existing scans work without ML; ML is opt-in via `ML_MODEL_URL`.
