"""
Shared training loop for train.py (dependency model) and train-behavioral.py.

    1. time-stratified held-out split (dataset_split.py)
    2. optional minority oversampling / scale_pos_weight on the train split
    3. fit, score the held-out split (precision, recall, F1, ROC-AUC, PR-AUC, Brier)
    4. refit on every row for the shipped booster; Platt scaling from
       out-of-fold margins (one exportable booster, no CalibratedClassifierCV)
    5. save as XGBoost JSON + calibration + hashed metadata (model_io.py)

The held-out metrics are measured before the refit sees those rows, so they
are the estimate recorded in metadata; `refit_on_all_rows` says the shipped
booster has seen more data than the one that was scored.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

from dataset_split import dataset_summary, heldout_metrics, time_stratified_split
from model_io import fit_platt, save_model

try:
    import xgboost as xgb
    from sklearn.metrics import classification_report
except ImportError as e:  # pragma: no cover
    print("Install: pip install scikit-learn xgboost", file=sys.stderr)
    raise e


def oversample(X: Sequence[Sequence[float]], y: Sequence[int]) -> Tuple[List[List[float]], List[int]]:
    """Oversample the minority class with replacement (returns copies)."""
    from sklearn.utils import resample

    pos = [i for i, v in enumerate(y) if v == 1]
    neg = [i for i, v in enumerate(y) if v == 0]
    if not pos or not neg or len(pos) == len(neg):
        return [list(x) for x in X], list(y)
    minority, majority = (pos, neg) if len(pos) < len(neg) else (neg, pos)
    min_X, min_y = resample(
        [list(X[i]) for i in minority], [y[i] for i in minority], n_samples=len(majority), random_state=42, replace=True
    )
    return [list(X[i]) for i in majority] + list(min_X), [y[i] for i in majority] + list(min_y)


def oof_margins(X: Sequence[Sequence[float]], y: Sequence[int], xgb_kw: Dict[str, Any]) -> Optional[np.ndarray]:
    """Out-of-fold logit margins for Platt scaling."""
    from sklearn.model_selection import StratifiedKFold, cross_val_predict

    n_min = min(sum(1 for v in y if v == 1), sum(1 for v in y if v == 0))
    if n_min < 2:
        print("Calibration skipped: fewer than 2 samples in a class")
        return None
    folds = max(2, min(3, n_min))
    proba = cross_val_predict(
        xgb.XGBClassifier(**xgb_kw),
        np.asarray(X, dtype=float),
        np.asarray(y),
        cv=StratifiedKFold(n_splits=folds, shuffle=True, random_state=42),
        method="predict_proba",
    )[:, 1]
    proba = np.clip(proba, 1e-6, 1 - 1e-6)
    return np.log(proba / (1 - proba))


def drop_scanner_labelled_rows(rows: Sequence[Dict[str, Any]], allow: bool) -> List[Dict[str, Any]]:
    """Rows exported by `nullvoid scan --export-training*` carry `source: scanner-*`:
    their label is the scanner's own verdict, so training on them teaches the
    model the heuristics rather than malware. They are dropped unless the
    caller explicitly allows them."""
    scanner = [r for r in rows if str(r.get("source", "")).startswith("scanner-")]
    if not scanner or allow:
        if scanner:
            print(f"Warning: keeping {len(scanner)} scanner-labelled rows (--allow-scanner-labels)")
        return list(rows)
    print(f"Dropping {len(scanner)} scanner-labelled rows (labels must come from ground truth; pass --allow-scanner-labels to keep them)")
    return [r for r in rows if not str(r.get("source", "")).startswith("scanner-")]


def train_and_save(
    *,
    rows: Sequence[Dict[str, Any]],
    X: List[List[float]],
    y: List[int],
    feature_keys: List[str],
    schema_version: int,
    out_dir: Path,
    name: str,
    model_type: str,
    xgboost_params: Dict[str, Any],
    heldout_fraction: float,
    balance: bool,
    balance_class_weight: bool,
    calibrate: bool,
    refit: bool = True,
    tune: bool = False,
    extra_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if len(set(y)) < 2:
        print("Error: training data has only one class; add both benign and malicious samples.", file=sys.stderr)
        sys.exit(1)
    if balance and balance_class_weight:
        print("Use only one of --balance or --balance-class-weight.", file=sys.stderr)
        sys.exit(1)

    train_idx, test_idx, split_info = time_stratified_split(rows, y, heldout_fraction)
    X_train = [X[i] for i in train_idx]
    y_train = [y[i] for i in train_idx]
    X_test = [X[i] for i in test_idx]
    y_test = [y[i] for i in test_idx]
    n_pos = sum(1 for v in y if v == 1)
    n_neg = len(y) - n_pos
    print(f"Rows: {n_neg} benign, {n_pos} malicious; split {split_info['method']}: {len(y_train)} train / {len(y_test)} held-out")

    imbalance_strategy = "none"
    if balance and n_pos != n_neg:
        imbalance_strategy = "oversample"
        X_train, y_train = oversample(X_train, y_train)
        print(f"After oversampling: {sum(1 for v in y_train if v == 0)} benign, {sum(1 for v in y_train if v == 1)} malicious")
    elif balance_class_weight:
        imbalance_strategy = "scale_pos_weight"

    def spw(y_fit: Sequence[int]) -> float:
        p = sum(1 for v in y_fit if v == 1)
        n = len(y_fit) - p
        return float(n) / float(p) if imbalance_strategy == "scale_pos_weight" and p and n else 1.0

    xgb_kw = {**xgboost_params, "scale_pos_weight": spw(y_train)}
    best_params: Dict[str, Any] = {}
    if tune and len(X_train) >= 20:
        from sklearn.model_selection import GridSearchCV

        grid = {
            "max_depth": [4, 6, 8],
            "n_estimators": [80, 120, 180],
            "learning_rate": [0.05, 0.1, 0.2],
            "min_child_weight": [1, 3, 5],
        }
        base = {k: v for k, v in xgb_kw.items() if k not in grid}
        tuner = GridSearchCV(xgb.XGBClassifier(**base), grid, cv=3, scoring="average_precision", n_jobs=1)
        tuner.fit(X_train, y_train)
        best_params = dict(tuner.best_params_)
        xgb_kw.update(best_params)
        print(f"Tuned params: {best_params}")

    # 1. Fit on the train split; score held-out with the same calibration the shipped model gets.
    model = xgb.XGBClassifier(**xgb_kw)
    model.fit(X_train, y_train)

    metrics: Dict[str, Any] = {}
    if X_test:
        margin = model.get_booster().predict(xgb.DMatrix(np.asarray(X_test, dtype=float)), output_margin=True)
        platt = None
        if calibrate:
            m = oof_margins(X_train, y_train, xgb_kw)
            if m is not None:
                platt = fit_platt(m, np.asarray(y_train))
        if platt:
            y_proba = 1.0 / (1.0 + np.exp(np.clip(platt["a"] * margin + platt["b"], -500, 500)))
        else:
            y_proba = 1.0 / (1.0 + np.exp(np.clip(-margin, -500, 500)))
        metrics = heldout_metrics(y_test, y_proba)
        metrics["evaluated_on"] = f"held-out ({split_info['method']})"
        print(
            f"Held-out n={metrics['samples']} (pos {metrics['positives']}): precision {metrics['precision']:.3f} "
            f"recall {metrics['recall']:.3f} f1 {metrics['f1']:.3f} roc_auc {metrics.get('roc_auc', float('nan')):.3f} "
            f"pr_auc {metrics.get('pr_auc', float('nan')):.3f} brier {metrics['brier']:.3f}"
        )
        print(
            classification_report(
                y_test, (np.asarray(y_proba) >= 0.5).astype(int), target_names=["benign", "malicious"], labels=[0, 1], zero_division=0
            )
        )
    else:
        print("No held-out split (too few rows); metrics left empty")

    # 2. Refit on every row for the shipped booster.
    refit_on_all = refit and bool(X_test)
    if refit_on_all:
        X_fit, y_fit = oversample(X, y) if imbalance_strategy == "oversample" else ([list(x) for x in X], list(y))
        xgb_kw["scale_pos_weight"] = spw(y_fit)
        model = xgb.XGBClassifier(**xgb_kw)
        model.fit(X_fit, y_fit)
    else:
        X_fit, y_fit = X_train, y_train

    calib_margins = oof_margins(X_fit, y_fit, xgb_kw) if calibrate else None

    training_scores: List[float] = []
    try:
        training_scores = [float(p) for p in model.predict_proba(X_fit)[:500, 1]]
    except Exception:
        pass

    metadata: Dict[str, Any] = {
        "model_type": model_type + ("_calibrated" if calib_margins is not None else ""),
        "feature_keys": feature_keys,
        "feature_schema_version": schema_version,
        "training_date": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "dataset_size": len(rows),
        "class_distribution": {"good": n_neg, "bad": n_pos},
        "dataset": dataset_summary(rows, y),
        "split": split_info,
        "refit_on_all_rows": refit_on_all,
        "imbalance_strategy": imbalance_strategy,
        "xgboost_params": {k: v for k, v in xgb_kw.items() if k != "scale_pos_weight"},
        "tuned": bool(best_params),
        "best_params": best_params,
        "scale_pos_weight": round(float(xgb_kw["scale_pos_weight"]), 6),
        "metrics": metrics,
        "training_scores": training_scores,
    }
    if extra_metadata:
        metadata.update(extra_metadata)

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    hashes = save_model(model, out_dir, name, feature_keys, metadata, y_calib=y_fit, calib_margins=calib_margins)
    print(f"Model saved to {out_dir / f'{name}.model.json'} (sha256 {hashes['model'][:12]}…)")
    meta_name = "metadata.json" if name == "model" else f"{name}-metadata.json"
    print(f"Metadata saved to {out_dir / meta_name}")
    return metadata
