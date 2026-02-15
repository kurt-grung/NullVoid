#!/usr/bin/env python3
"""
Serve the trained model via FastAPI.
POST /score accepts {"features": {...}} and returns {"score": 0.0-1.0}.
Supports explain, batch scoring, model info, and feature importance.

Usage:
  python serve.py
  python serve.py --model model.pkl --port 8000
  python serve.py --model-dir models/v1 --port 8000
"""

import argparse
from pathlib import Path
from typing import Any, Optional

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
metadata = None
model_dir: Optional[Path] = None

# Human-readable reasons for top features (Phase 3.3)
FEATURE_REASONS: dict[str, str] = {
    "timelineAnomaly": "Package created very recently relative to repo history",
    "scopePrivate": "Private scope package may be vulnerable to dependency confusion",
    "suspiciousPatternsCount": "Package name follows suspicious naming patterns",
    "commitPatternAnomaly": "Unusual commit patterns (single author, low activity)",
    "nlpSecurityScore": "NLP analysis detected security-related phrases",
    "crossPackageAnomaly": "Cross-package behavioral anomaly detected",
    "behavioralAnomaly": "Behavioral anomaly in package metadata",
    "reviewSecurityScore": "Low community review/security score",
    "popularityScore": "Low popularity score",
    "trustScore": "Low trust score",
    "daysDifference": "Short time between package creation and first commit",
    "recentCommitCount": "Low recent commit activity",
    "dominantAuthorShare": "Single author dominates commits",
}


def get_base_estimator(m):
    """Extract base XGBoost estimator from CalibratedClassifierCV if wrapped."""
    if hasattr(m, "calibrated_classifiers_"):
        cal = m.calibrated_classifiers_
        if cal and len(cal) > 0:
            first = cal[0]
            if isinstance(first, tuple):
                base = first[0]
            else:
                base = first
            # _CalibratedClassifier wraps estimator; unwrap to get XGBoost
            if hasattr(base, "estimator") and hasattr(base.estimator, "feature_importances_"):
                return base.estimator
            if hasattr(base, "feature_importances_"):
                return base
    return m


def get_feature_importance() -> dict[str, float]:
    """Extract feature importance from model (XGBoost)."""
    base = get_base_estimator(model)
    if base is None or not hasattr(base, "feature_importances_"):
        return {}
    keys = feature_keys or []
    imp = base.feature_importances_
    return {k: float(imp[i]) for i, k in enumerate(keys) if i < len(imp)}


def get_top_reasons(feats: dict, importance: dict[str, float], top_n: int = 5) -> list[str]:
    """Map top contributing features to human-readable reasons."""
    sorted_keys = sorted(importance.keys(), key=lambda k: importance.get(k, 0), reverse=True)
    reasons = []
    for k in sorted_keys[:top_n]:
        imp = importance.get(k, 0)
        if imp <= 0:
            continue
        val = feats.get(k, 0)
        reason = FEATURE_REASONS.get(k)
        if reason:
            reasons.append(f"{k}={val:.2f}: {reason}")
        else:
            reasons.append(f"{k}={val:.2f}")
    return reasons


def load_model(path: Path, dir_path: Optional[Path] = None):
    global model, feature_keys, metadata, model_dir
    model_dir = dir_path or path.parent
    model = joblib.load(path)
    keys_path = model_dir / "feature_keys.pkl"
    feature_keys = joblib.load(keys_path) if keys_path.exists() else [
        "daysDifference", "recentCommitCount", "scopePrivate", "suspiciousPatternsCount",
        "timelineAnomaly", "registryIsNpm", "authorCount", "totalCommitCount",
        "dominantAuthorShare", "commitPatternAnomaly", "branchCount", "recentCommitCount90d",
        "messageAnomalyScore", "diffAnomalyScore", "nlpSecurityScore", "nlpSuspiciousCount",
        "crossPackageAnomaly", "behavioralAnomaly", "reviewSecurityScore", "popularityScore",
        "trustScore",
    ]
    meta_path = model_dir / "metadata.json"
    if meta_path.exists():
        import json
        with open(meta_path) as f:
            metadata = json.load(f)
    else:
        metadata = {"model_type": "unknown", "feature_keys": feature_keys}


class ScoreRequest(BaseModel):
    features: dict
    explain: bool = False


class BatchScoreRequest(BaseModel):
    features_list: list[dict]
    explain: bool = False


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
        result: dict[str, Any] = {"score": float(bad_prob)}
        if req.explain:
            importance = get_feature_importance()
            result["importance"] = importance
            result["reasons"] = get_top_reasons(req.features, importance)
        return result
    except Exception as e:
        return {"score": 0.5, "error": str(e)}


@app.post("/batch-score")
def batch_score(req: BatchScoreRequest) -> dict:
    if model is None:
        return {"scores": [], "error": "Model not loaded"}
    try:
        vectors = [extract_vector(f) for f in req.features_list]
        probas = model.predict_proba(vectors)
        scores = [float(p[1] if len(p) > 1 else p[0]) for p in probas]
        result: dict[str, Any] = {"scores": scores}
        if req.explain and req.features_list:
            importance = get_feature_importance()
            result["importance"] = importance
            result["reasons_list"] = [get_top_reasons(f, importance) for f in req.features_list]
        return result
    except Exception as e:
        return {"scores": [], "error": str(e)}


@app.get("/importance")
def importance_endpoint() -> dict:
    if model is None:
        return {"error": "Model not loaded"}
    return {"importance": get_feature_importance(), "feature_keys": feature_keys or []}


@app.get("/model-info")
def model_info() -> dict:
    return {
        "loaded": model is not None,
        "model_dir": str(model_dir) if model_dir else None,
        "metadata": metadata or {},
    }


@app.get("/explain")
def explain_get() -> dict:
    """Returns global feature importance. Use POST /score with explain=true for per-request reasons."""
    if model is None:
        return {"error": "Model not loaded"}
    return {"importance": get_feature_importance(), "feature_keys": feature_keys or []}


@app.post("/explain")
def explain_post(req: ScoreRequest) -> dict:
    """Per-sample explanation: top contributing features for the given feature vector.
    Uses SHAP when available, otherwise falls back to feature importance * feature values."""
    if model is None:
        return {"error": "Model not loaded"}
    vec = extract_vector(req.features)
    importance = get_feature_importance()
    keys = feature_keys or []
    contributions = {k: importance.get(k, 0) * req.features.get(k, 0) for k in keys}
    sorted_contrib = sorted(contributions.items(), key=lambda x: abs(x[1]), reverse=True)
    top = dict(sorted_contrib[:10])
    reasons = get_top_reasons(req.features, importance, top_n=5)
    try:
        import shap
        base = get_base_estimator(model)
        if base is not None and hasattr(base, "predict_proba"):
            explainer = shap.TreeExplainer(base)
            shap_vals = explainer.shap_values([vec])
            if isinstance(shap_vals, list):
                shap_vals = shap_vals[1] if len(shap_vals) > 1 else shap_vals[0]
            if shap_vals is not None and len(shap_vals) > 0:
                sv = shap_vals[0]
                top = {keys[i]: float(sv[i]) for i in range(min(len(keys), len(sv)))}
                top = dict(sorted(top.items(), key=lambda x: abs(x[1]), reverse=True)[:10])
    except ImportError:
        pass
    return {"contributions": top, "reasons": reasons}


@app.get("/health")
def health():
    return {"ok": model is not None}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", "-m", help="Path to model.pkl")
    ap.add_argument("--model-dir", help="Model directory (model.pkl, feature_keys.pkl, metadata.json)")
    ap.add_argument("--port", "-p", type=int, default=8000)
    args = ap.parse_args()

    path = None
    dir_path = None
    if args.model_dir:
        dir_path = Path(args.model_dir)
        path = dir_path / "model.pkl"
    else:
        path = Path(args.model or str(MODEL_PATH))

    if path.exists():
        load_model(path, dir_path)
    else:
        print(f"Warning: {path} not found. Train first: python train.py --input train.jsonl")

    run(app, host="0.0.0.0", port=args.port)
