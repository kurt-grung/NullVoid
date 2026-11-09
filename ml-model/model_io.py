"""
Model serialisation without pickle.

Pickle / joblib files execute arbitrary code on load, so a model committed to
git (or produced by a retrain workflow) is a code-execution path into every
machine that runs the ML service. Models are stored instead as:

  <name>.model.json    XGBoost booster in its native JSON format
  <name>.calib.json    Platt scaling (sigmoid) parameters a, b, or null when
                       the model is uncalibrated
  <name>-metadata.json records sha256 of both files; load_model refuses a
                       file whose hash does not match

Loading returns a CalibratedBooster with predict_proba / predict, so callers
written against sklearn's API (serve.py, evaluate.py) do not change.
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import numpy as np

try:
    import xgboost as xgb
except ImportError:  # pragma: no cover - import guard
    xgb = None  # type: ignore[assignment]


class ModelIntegrityError(RuntimeError):
    """Raised when a model file does not match the hash recorded in metadata."""


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class CalibratedBooster:
    """An XGBoost booster plus optional Platt scaling, exposing sklearn-ish methods."""

    def __init__(self, booster: "xgb.Booster", feature_keys: List[str], calibration: Optional[Dict[str, float]]):
        self.booster = booster
        self.feature_keys = list(feature_keys)
        self.calibration = calibration  # {"a": float, "b": float} or None

    def _margin(self, X: Sequence[Sequence[float]]) -> np.ndarray:
        arr = np.asarray(X, dtype=float)
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)
        dm = xgb.DMatrix(arr, feature_names=self.feature_keys if arr.shape[1] == len(self.feature_keys) else None)
        return self.booster.predict(dm, output_margin=True)

    def predict_proba(self, X: Sequence[Sequence[float]]) -> np.ndarray:
        margin = self._margin(X)
        if self.calibration:
            a = float(self.calibration["a"])
            b = float(self.calibration["b"])
            p = 1.0 / (1.0 + np.exp(np.clip(a * margin + b, -500, 500)))
        else:
            p = 1.0 / (1.0 + np.exp(np.clip(-margin, -500, 500)))
        p = np.clip(p, 0.0, 1.0)
        return np.column_stack([1.0 - p, p])

    def predict(self, X: Sequence[Sequence[float]]) -> np.ndarray:
        return (self.predict_proba(X)[:, 1] >= 0.5).astype(int)

    # Compatibility shims for code that introspects sklearn objects.
    @property
    def classes_(self) -> np.ndarray:
        return np.array([0, 1])

    def get_booster(self) -> "xgb.Booster":
        return self.booster


def _extract_booster(model: Any) -> "xgb.Booster":
    """Pull the underlying xgboost Booster out of an XGBClassifier or a CalibratedClassifierCV."""
    if isinstance(model, xgb.Booster):
        return model
    if hasattr(model, "get_booster"):
        return model.get_booster()
    # CalibratedClassifierCV: calibrated_classifiers_[i].estimator (sklearn >= 1.2)
    cc = getattr(model, "calibrated_classifiers_", None)
    if cc:
        est = getattr(cc[0], "estimator", None) or getattr(cc[0], "base_estimator", None)
        if est is not None and hasattr(est, "get_booster"):
            return est.get_booster()
    raise TypeError(f"cannot extract an xgboost Booster from {type(model).__name__}")


def fit_platt(margins: np.ndarray, y: np.ndarray, l2: float = 1e-3) -> Dict[str, float]:
    """
    Fit sigmoid calibration p = 1 / (1 + exp(a*m + b)), the form sklearn's
    CalibratedClassifierCV(method='sigmoid') uses. Prefers sklearn's own
    solver when importable; otherwise a bounded Newton fit on Platt's
    prior-corrected targets with a small L2 penalty on a.
    """
    m = np.asarray(margins, dtype=float)
    y = np.asarray(y, dtype=float)
    if len(y) == 0 or len(set(y.tolist())) < 2:
        return {"a": -1.0, "b": 0.0}  # identity sigmoid
    try:
        from sklearn.calibration import _SigmoidCalibration  # type: ignore

        sc = _SigmoidCalibration().fit(m, y)
        return {"a": float(sc.a_), "b": float(sc.b_)}
    except Exception:
        pass

    n_pos = float(y.sum())
    n_neg = float(len(y) - n_pos)
    t = np.where(y > 0, (n_pos + 1.0) / (n_pos + 2.0), 1.0 / (n_neg + 2.0))
    a, b = -1.0, 0.0
    for _ in range(200):
        z = np.clip(a * m + b, -500, 500)
        p = 1.0 / (1.0 + np.exp(z))  # P(y=1)
        # NLL = -sum t*log p + (1-t)*log(1-p); dNLL/dz = (t - p)  (since dp/dz = -p(1-p))
        d = t - p
        w = np.maximum(p * (1.0 - p), 1e-12)
        g_a = float(np.sum(d * m)) + l2 * a
        g_b = float(np.sum(d))
        h_aa = float(np.sum(w * m * m)) + l2
        h_ab = float(np.sum(w * m))
        h_bb = float(np.sum(w)) + 1e-12
        det = h_aa * h_bb - h_ab * h_ab
        if abs(det) < 1e-18:
            break
        da = (h_bb * g_a - h_ab * g_b) / det
        db = (h_aa * g_b - h_ab * g_a) / det
        a -= da
        b -= db
        a = float(np.clip(a, -20.0, 20.0))
        b = float(np.clip(b, -50.0, 50.0))
        if abs(da) < 1e-9 and abs(db) < 1e-9:
            break
    return {"a": float(a), "b": float(b)}


def save_model(
    model: Any,
    out_dir: Path,
    name: str,
    feature_keys: List[str],
    metadata: Dict[str, Any],
    X_calib: Optional[Sequence[Sequence[float]]] = None,
    y_calib: Optional[Sequence[int]] = None,
    calib_margins: Optional[Sequence[float]] = None,
) -> Dict[str, str]:
    """
    Write <name>.model.json, <name>.calib.json and <name>-metadata.json (or
    metadata.json when name == 'model', matching the existing layout).
    Returns the file hashes that were recorded.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    booster = _extract_booster(model)

    model_path = out_dir / f"{name}.model.json"
    booster.save_model(str(model_path))

    calibration: Optional[Dict[str, float]] = None
    if calib_margins is not None and y_calib is not None and len(y_calib) > 0:
        # Preferred: out-of-fold margins supplied by the trainer.
        calibration = fit_platt(np.asarray(calib_margins, dtype=float), np.asarray(y_calib))
    elif hasattr(model, "calibrated_classifiers_") and X_calib is not None and y_calib is not None and len(y_calib) > 0:
        margins = booster.predict(xgb.DMatrix(np.asarray(X_calib, dtype=float)), output_margin=True)
        calibration = fit_platt(margins, np.asarray(y_calib))
    calib_path = out_dir / f"{name}.calib.json"
    with open(calib_path, "w", encoding="utf-8") as f:
        json.dump({"method": "sigmoid" if calibration else None, "params": calibration, "feature_keys": list(feature_keys)}, f, indent=2)

    hashes = {"model": sha256_file(model_path), "calibration": sha256_file(calib_path)}
    meta = dict(metadata)
    meta["artifacts"] = {
        "format": "xgboost-json+platt",
        "model_file": model_path.name,
        "calibration_file": calib_path.name,
        "sha256": hashes,
    }
    meta_path = out_dir / ("metadata.json" if name == "model" else f"{name}-metadata.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    return hashes


def load_model(dir_path: Path, name: str = "model", verify: bool = True) -> tuple[CalibratedBooster, Dict[str, Any]]:
    """
    Load <name>.model.json + <name>.calib.json from dir_path, verifying their
    sha256 against the metadata file. Raises ModelIntegrityError on mismatch
    or when metadata has no hashes (an unsigned artifact).
    """
    if xgb is None:
        raise ImportError("xgboost is required to load models")
    dir_path = Path(dir_path)
    meta_path = dir_path / ("metadata.json" if name == "model" else f"{name}-metadata.json")
    with open(meta_path, encoding="utf-8") as f:
        metadata = json.load(f)

    artifacts = metadata.get("artifacts") or {}
    model_path = dir_path / artifacts.get("model_file", f"{name}.model.json")
    calib_path = dir_path / artifacts.get("calibration_file", f"{name}.calib.json")

    if verify:
        recorded = artifacts.get("sha256") or {}
        if not recorded:
            raise ModelIntegrityError(f"{meta_path.name} records no artifact hashes; refusing to load an unsigned model")
        for label, path in (("model", model_path), ("calibration", calib_path)):
            actual = sha256_file(path)
            if actual != recorded.get(label):
                raise ModelIntegrityError(f"{path.name} sha256 {actual[:12]}… does not match metadata {str(recorded.get(label))[:12]}…")

    booster = xgb.Booster()
    booster.load_model(str(model_path))
    with open(calib_path, encoding="utf-8") as f:
        calib = json.load(f)
    feature_keys = calib.get("feature_keys") or metadata.get("feature_keys") or []
    return CalibratedBooster(booster, feature_keys, calib.get("params")), metadata


class LinearStacker:
    """A logistic-regression stacker over [dependency_score, behavioral_score], stored as JSON."""

    def __init__(self, coef: Sequence[float], intercept: float):
        self.coef = np.asarray(coef, dtype=float)
        self.intercept = float(intercept)

    def predict_proba(self, X: Sequence[Sequence[float]]) -> np.ndarray:
        arr = np.asarray(X, dtype=float)
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)
        z = arr @ self.coef + self.intercept
        p = 1.0 / (1.0 + np.exp(-z))
        return np.column_stack([1.0 - p, p])

    def predict(self, X: Sequence[Sequence[float]]) -> np.ndarray:
        return (self.predict_proba(X)[:, 1] >= 0.5).astype(int)


def save_stacker(model: Any, path: Path, metadata_path: Path, metadata: Dict[str, Any]) -> str:
    """Write a sklearn LogisticRegression as JSON and record its hash in metadata."""
    path = Path(path)
    coef = [float(c) for c in np.asarray(model.coef_).ravel()]
    intercept = float(np.asarray(model.intercept_).ravel()[0])
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"type": "logreg_stacker", "coef": coef, "intercept": intercept}, f, indent=2)
    digest = sha256_file(path)
    meta = dict(metadata)
    meta["artifacts"] = {"format": "logreg-json", "model_file": path.name, "sha256": {"model": digest}}
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    return digest


def load_stacker(path: Path, metadata_path: Optional[Path] = None, verify: bool = True) -> LinearStacker:
    path = Path(path)
    if verify:
        mp = Path(metadata_path) if metadata_path else path.with_name("ensemble-metadata.json")
        with open(mp, encoding="utf-8") as f:
            recorded = ((json.load(f).get("artifacts") or {}).get("sha256") or {}).get("model")
        if not recorded:
            raise ModelIntegrityError(f"{mp.name} records no hash for {path.name}")
        actual = sha256_file(path)
        if actual != recorded:
            raise ModelIntegrityError(f"{path.name} sha256 does not match {mp.name}")
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    return LinearStacker(d["coef"], d["intercept"])
