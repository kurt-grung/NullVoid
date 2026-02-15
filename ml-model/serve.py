#!/usr/bin/env python3
"""
Serve the trained model via FastAPI.
POST /score accepts {"features": {...}} and returns {"score": 0.0-1.0}.

Usage:
  python serve.py
  python serve.py --model model.pkl --port 8000
"""

import argparse
from pathlib import Path

try:
    import joblib
    from fastapi import FastAPI
    from pydantic import BaseModel
    from uvicorn import run
except ImportError:
    print("Install: pip install fastapi uvicorn scikit-learn joblib", file=__import__("sys").stderr)
    raise

app = FastAPI(title="NullVoid ML Score API")

MODEL_PATH = Path(__file__).parent / "model.pkl"
KEYS_PATH = Path(__file__).parent / "feature_keys.pkl"

model = None
feature_keys = None


def load_model(path: Path):
    global model, feature_keys
    model = joblib.load(path)
    keys_path = path.parent / "feature_keys.pkl"
    feature_keys = joblib.load(keys_path) if keys_path.exists() else [
        "daysDifference", "recentCommitCount", "scopePrivate", "suspiciousPatternsCount",
        "timelineAnomaly", "registryIsNpm", "authorCount", "totalCommitCount",
        "dominantAuthorShare", "commitPatternAnomaly", "branchCount", "recentCommitCount90d",
        "messageAnomalyScore", "diffAnomalyScore", "nlpSecurityScore", "nlpSuspiciousCount",
        "crossPackageAnomaly", "behavioralAnomaly", "reviewSecurityScore", "popularityScore",
        "trustScore",
    ]


class ScoreRequest(BaseModel):
    features: dict


def extract_vector(feats: dict) -> list[float]:
    keys = feature_keys or []
    return [float(feats.get(k, 0)) for k in keys]


@app.post("/score")
def score(req: ScoreRequest) -> dict:
    if model is None:
        return {"score": 0.5, "error": "Model not loaded"}
    try:
        vec = extract_vector(req.features)
        proba = model.predict_proba([vec])[0]
        bad_prob = proba[1] if len(proba) > 1 else proba[0]
        return {"score": float(bad_prob)}
    except Exception as e:
        return {"score": 0.5, "error": str(e)}


@app.get("/health")
def health():
    return {"ok": model is not None}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", "-m", default=str(MODEL_PATH))
    ap.add_argument("--port", "-p", type=int, default=8000)
    args = ap.parse_args()

    path = Path(args.model)
    if path.exists():
        load_model(path)
    else:
        print(f"Warning: {path} not found. Train first: python train.py --input train.jsonl")

    run(app, host="0.0.0.0", port=args.port)
