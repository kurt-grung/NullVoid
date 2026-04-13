#!/usr/bin/env python3
"""
Serve the trained model via FastAPI.
POST /score accepts {"features": {...}} and returns {"score": 0.0-1.0}.
Supports explain, batch scoring, model info, and feature importance.
GET /health returns ok, behavioral_loaded, and shap (whether SHAP is installed).

Usage:
  python serve.py
  python serve.py --model model.pkl --port 8000
  python serve.py --model-dir models/v1 --port 8000
"""

import argparse
import json
import os
from pathlib import Path
from typing import Any, Optional

DEFAULT_MAX_BATCH = 512

try:
    import joblib
    from fastapi import FastAPI
    from pydantic import BaseModel
    from uvicorn import run
except ImportError:
    print("Install: pip install fastapi uvicorn scikit-learn joblib", file=__import__("sys").stderr)
    raise


def _shap_available() -> bool:
    try:
        import shap  # noqa: F401

        return True
    except ImportError:
        return False


SHAP_AVAILABLE = _shap_available()

app = FastAPI(title="NullVoid ML Score API")

MODEL_PATH = Path(__file__).parent / "model.pkl"
KEYS_PATH = Path(__file__).parent / "feature_keys.pkl"

model = None
feature_keys = None
metadata = None
model_dir: Optional[Path] = None
feature_schema_version: Optional[int] = None

# Behavioral model (package scripts)
behavioral_model = None
behavioral_feature_keys: Optional[list] = None
behavioral_model_dir: Optional[Path] = None
behavioral_metadata: Optional[dict] = None
ensemble_model = None

SCORE_LOG_PATH = Path(__file__).parent / "score-history.jsonl"
MAX_SCORE_HISTORY = 2000

BEHAVIORAL_FEATURE_KEYS = [
    "scriptCount", "scriptTotalLength", "hasPostinstall", "postinstallLength",
    "preinstallLength", "postuninstallLength", "networkScriptCount", "evalUsageCount",
    "childProcessCount", "fileSystemAccessCount", "base64DecodeCount", "obfuscationMarkerCount",
    "socketDnsCount", "dependencyCount", "devDependencyCount",
]

BEHAVIORAL_FEATURE_REASONS: dict[str, str] = {
    "scriptCount": "Unusual number of lifecycle scripts",
    "scriptTotalLength": "Large total script content",
    "hasPostinstall": "Has postinstall script (common attack vector)",
    "postinstallLength": "Long postinstall script",
    "preinstallLength": "Long preinstall script",
    "postuninstallLength": "Long postuninstall script",
    "networkScriptCount": "Scripts contain network/fetch/curl",
    "evalUsageCount": "Scripts use eval or Function constructor",
    "childProcessCount": "Scripts spawn child processes",
    "fileSystemAccessCount": "Scripts access file system",
    "base64DecodeCount": "Scripts decode Base64 payloads",
    "obfuscationMarkerCount": "Scripts contain obfuscation markers",
    "socketDnsCount": "Scripts use DNS/socket APIs",
    "dependencyCount": "Dependency count",
    "devDependencyCount": "Dev dependency count",
}

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
    global feature_schema_version
    if meta_path.exists():
        with open(meta_path, encoding="utf-8") as f:
            metadata = json.load(f)
        feature_schema_version = metadata.get("feature_schema_version")
    else:
        metadata = {"model_type": "unknown", "feature_keys": feature_keys}
        feature_schema_version = None


def load_behavioral_model(dir_path: Path):
    global behavioral_model, behavioral_feature_keys, behavioral_model_dir, behavioral_metadata, ensemble_model
    model_path = dir_path / "behavioral-model.pkl"
    if not model_path.exists():
        return
    behavioral_model = joblib.load(model_path)
    keys_path = dir_path / "behavioral-feature_keys.pkl"
    behavioral_feature_keys = (
        joblib.load(keys_path) if keys_path.exists() else BEHAVIORAL_FEATURE_KEYS
    )
    behavioral_model_dir = dir_path
    meta_path = dir_path / "behavioral-metadata.json"
    if meta_path.exists():
        with open(meta_path, encoding="utf-8") as f:
            behavioral_metadata = json.load(f)
    else:
        behavioral_metadata = {"model_type": "unknown", "feature_keys": behavioral_feature_keys}
    ensemble_path = dir_path / "ensemble-model.pkl"
    if ensemble_path.exists():
        ensemble_model = joblib.load(ensemble_path)


def extract_behavioral_vector(feats: dict) -> list[float]:
    keys = behavioral_feature_keys or BEHAVIORAL_FEATURE_KEYS
    return [float(feats.get(k, 0)) for k in keys]


def append_score_history(kind: str, score: float) -> None:
    try:
        with open(SCORE_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": __import__("time").time(), "kind": kind, "score": float(score)}) + "\n")
    except OSError:
        pass


def load_recent_scores(kind: str, limit: int = 500) -> list[float]:
    if not SCORE_LOG_PATH.exists():
        return []
    rows: list[float] = []
    try:
        with open(SCORE_LOG_PATH, encoding="utf-8") as f:
            for line in f:
                try:
                    obj = json.loads(line)
                    if obj.get("kind") == kind and isinstance(obj.get("score"), (int, float)):
                        rows.append(float(obj["score"]))
                except json.JSONDecodeError:
                    continue
    except OSError:
        return []
    return rows[-limit:]


def extract_training_scores(meta: Optional[dict]) -> list[float]:
    if not isinstance(meta, dict):
        return []
    scores = meta.get("training_scores")
    if isinstance(scores, list):
        return [float(x) for x in scores if isinstance(x, (int, float))]
    return []


def ks_statistic(a: list[float], b: list[float]) -> float:
    if not a or not b:
        return 0.0
    a_sorted = sorted(a)
    b_sorted = sorted(b)
    i = 0
    j = 0
    n = len(a_sorted)
    m = len(b_sorted)
    d = 0.0
    while i < n and j < m:
        if a_sorted[i] <= b_sorted[j]:
            i += 1
        else:
            j += 1
        cdf_a = i / n
        cdf_b = j / m
        d = max(d, abs(cdf_a - cdf_b))
    return float(d)


def get_behavioral_top_reasons(feats: dict, importance: dict[str, float], top_n: int = 5) -> list[str]:
    sorted_keys = sorted(importance.keys(), key=lambda k: importance.get(k, 0), reverse=True)
    reasons = []
    for k in sorted_keys[:top_n]:
        imp = importance.get(k, 0)
        if imp <= 0:
            continue
        val = feats.get(k, 0)
        reason = BEHAVIORAL_FEATURE_REASONS.get(k)
        if reason:
            reasons.append(f"{k}={val:.2f}: {reason}")
        else:
            reasons.append(f"{k}={val:.2f}")
    return reasons


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
        append_score_history("dependency", float(bad_prob))
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
    max_batch = int(os.environ.get("NULLVOID_ML_MAX_BATCH", str(DEFAULT_MAX_BATCH)))
    if max_batch < 1:
        max_batch = DEFAULT_MAX_BATCH
    n = len(req.features_list)
    if n > max_batch:
        return {
            "scores": [],
            "error": f"Batch too large: {n} items (max {max_batch}; set NULLVOID_ML_MAX_BATCH)",
        }
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
    manifest_path = Path(__file__).parent / "feature-keys.json"
    manifest_version = None
    if manifest_path.is_file():
        try:
            with open(manifest_path, encoding="utf-8") as f:
                manifest_version = json.load(f).get("version")
        except (json.JSONDecodeError, OSError):
            pass
    dep_meta = dict(metadata or {})
    dep_meta.setdefault("feature_schema_version", feature_schema_version)
    beh_meta = dict(behavioral_metadata or {}) if behavioral_model is not None else None
    return {
        "loaded": model is not None,
        "model_dir": str(model_dir) if model_dir else None,
        "metadata": dep_meta,
        "feature_keys_manifest_version": manifest_version,
        "behavioral_loaded": behavioral_model is not None,
        "behavioral_model_dir": str(behavioral_model_dir) if behavioral_model_dir else None,
        "behavioral_metadata": beh_meta,
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
    if SHAP_AVAILABLE:
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
        except Exception:
            pass
    return {"contributions": top, "reasons": reasons, "shap": SHAP_AVAILABLE}


@app.post("/behavioral-score")
def behavioral_score(req: ScoreRequest) -> dict:
    """Score package behavioral features (scripts, network, eval, etc.)."""
    if behavioral_model is None:
        return {"score": 0.5, "error": "Behavioral model not loaded"}
    try:
        vec = extract_behavioral_vector(req.features)
        proba = behavioral_model.predict_proba([vec])[0]
        bad_prob = proba[1] if len(proba) > 1 else proba[0]
        append_score_history("behavioral", float(bad_prob))
        result: dict[str, Any] = {"score": float(bad_prob)}
        if req.explain and behavioral_feature_keys:
            base = get_base_estimator(behavioral_model)
            if base is not None and hasattr(base, "feature_importances_"):
                imp = base.feature_importances_
                importance = {k: float(imp[i]) for i, k in enumerate(behavioral_feature_keys) if i < len(imp)}
                result["importance"] = importance
                result["reasons"] = get_behavioral_top_reasons(req.features, importance)
        return result
    except Exception as e:
        return {"score": 0.5, "error": str(e)}


@app.post("/ensemble-score")
def ensemble_score(req: ScoreRequest) -> dict:
    """Blend dependency + behavioral probabilities via trained stacker."""
    if model is None or behavioral_model is None:
        return {"score": 0.5, "error": "Base models not loaded"}
    if ensemble_model is None:
        return {"score": 0.5, "error": "Ensemble model not loaded"}
    try:
        dep_vec = extract_vector(req.features)
        beh_vec = extract_behavioral_vector(req.features)
        dep_proba = model.predict_proba([dep_vec])[0]
        beh_proba = behavioral_model.predict_proba([beh_vec])[0]
        dep_bad = float(dep_proba[1] if len(dep_proba) > 1 else dep_proba[0])
        beh_bad = float(beh_proba[1] if len(beh_proba) > 1 else beh_proba[0])
        score = float(ensemble_model.predict_proba([[dep_bad, beh_bad]])[0][1])
        append_score_history("ensemble", score)
        return {
            "score": score,
            "dependency_score": dep_bad,
            "behavioral_score": beh_bad,
        }
    except Exception as e:
        return {"score": 0.5, "error": str(e)}


@app.get("/drift")
def drift() -> dict:
    dep_recent = load_recent_scores("dependency")
    beh_recent = load_recent_scores("behavioral")
    ens_recent = load_recent_scores("ensemble")
    dep_train = extract_training_scores(metadata)
    beh_train = extract_training_scores(behavioral_metadata)
    dep_ks = ks_statistic(dep_train, dep_recent) if dep_train and dep_recent else 0.0
    beh_ks = ks_statistic(beh_train, beh_recent) if beh_train and beh_recent else 0.0
    ens_ks = 0.0
    drift_threshold = 0.2
    return {
        "driftDetected": dep_ks >= drift_threshold or beh_ks >= drift_threshold or ens_ks >= drift_threshold,
        "ksStatistic": max(dep_ks, beh_ks, ens_ks),
        "dependency": {"ksStatistic": dep_ks, "recentCount": len(dep_recent), "trainCount": len(dep_train)},
        "behavioral": {"ksStatistic": beh_ks, "recentCount": len(beh_recent), "trainCount": len(beh_train)},
        "ensemble": {"ksStatistic": ens_ks, "recentCount": len(ens_recent), "trainCount": 0},
        "threshold": drift_threshold,
    }


@app.get("/health")
def health():
    return {
        "ok": model is not None,
        "behavioral_loaded": behavioral_model is not None,
        "ensemble_loaded": ensemble_model is not None,
        "shap": SHAP_AVAILABLE,
    }


if __name__ == "__main__":
    import os
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", "-m", help="Path to model.pkl")
    ap.add_argument("--model-dir", help="Model directory (model.pkl, feature_keys.pkl, metadata.json)")
    ap.add_argument("--behavioral-model-dir", help="Behavioral model directory (behavioral-model.pkl, behavioral-feature_keys.pkl)")
    ap.add_argument("--ensemble-model", help="Path to ensemble-model.pkl (optional)")
    ap.add_argument("--port", "-p", type=int, default=int(os.environ.get("PORT", "8000")))
    args = ap.parse_args()
    port = args.port if args.port is not None else int(os.environ.get("PORT", 8000))

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

    if args.behavioral_model_dir:
        bdir = Path(args.behavioral_model_dir)
        if (bdir / "behavioral-model.pkl").exists():
            load_behavioral_model(bdir)
            print("Behavioral model loaded from", bdir)
        else:
            print(f"Warning: behavioral model not found in {bdir}")
    if args.ensemble_model:
        ep = Path(args.ensemble_model)
        if ep.exists():
            ensemble_model = joblib.load(ep)
            print("Ensemble model loaded from", ep)
        else:
            print(f"Warning: ensemble model not found at {ep}")

    run(app, host="0.0.0.0", port=port)
