#!/usr/bin/env python3
"""
Train an XGBoost model for dependency confusion threat scoring.
Reads JSONL from stdin or --input, outputs model.pkl, calibration.pkl, feature_keys.pkl, metadata.json.

Usage:
  python train.py --input train.jsonl
  python train.py --input train.jsonl --balance --calibrate
  python train.py --input train.jsonl --balance-class-weight --calibrate
  cat train.jsonl | python train.py
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

try:
    import joblib
    import xgboost as xgb
    from sklearn.calibration import CalibratedClassifierCV
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, classification_report, roc_auc_score, precision_score, recall_score
except ImportError as e:
    print("Install: pip install scikit-learn xgboost joblib", file=sys.stderr)
    raise e

_MANIFEST_PATH = Path(__file__).parent / "feature-keys.json"
_manifest = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
FEATURE_KEYS: List[str] = _manifest["dependency"]
FEATURE_SCHEMA_VERSION = int(_manifest.get("version", 1))

# Pinned XGBoost settings (documented in README); change only with held-out eval.
XGBOOST_PARAMS = {
    "n_estimators": 100,
    "max_depth": 6,
    "learning_rate": 0.1,
    "subsample": 0.9,
    "colsample_bytree": 0.9,
    "min_child_weight": 1,
    "random_state": 42,
    "eval_metric": "logloss",
}


def load_jsonl(path: Optional[str]) -> list:
    rows = []
    if path and Path(path).exists():
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
    else:
        for line in sys.stdin:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def extract_features(row: Dict) -> List[float]:
    feats = row.get("features", row)
    return [float(feats.get(k, 0)) for k in FEATURE_KEYS]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", "-i", help="Input JSONL file")
    ap.add_argument("--output", "-o", default="model.pkl", help="Output model path")
    ap.add_argument("--output-dir", help="Output directory (saves model, calibration, feature_keys, metadata)")
    ap.add_argument("--test-size", type=float, default=0.2, help="Test set fraction")
    ap.add_argument("--balance", action="store_true", help="Balance classes (oversample minority)")
    ap.add_argument(
        "--balance-class-weight",
        action="store_true",
        help="Balance via XGBoost scale_pos_weight only (no oversampling). Mutually exclusive with --balance.",
    )
    ap.add_argument("--calibrate", action="store_true", default=True, help="Apply Platt scaling for probability calibration (default: True)")
    ap.add_argument("--no-calibrate", action="store_true", help="Disable probability calibration")
    args = ap.parse_args()

    if args.balance and args.balance_class_weight:
        print("Use only one of --balance or --balance-class-weight.", file=sys.stderr)
        sys.exit(1)

    do_calibrate = args.calibrate and not args.no_calibrate

    rows = load_jsonl(args.input)
    if not rows:
        print("No data. Provide --input or pipe JSONL.", file=sys.stderr)
        sys.exit(1)

    X = [extract_features(r) for r in rows]
    y = [int(r.get("label", 0)) for r in rows]

    classes = set(y)
    if len(classes) < 2:
        print(
            "Error: Training data has only one class (label 0 = benign). "
            "Add malware samples by running:\n"
            "  nullvoid scan /path/to/malware --no-ioc --train\n"
            "  node ml-model/export-features.js --from-ghsa --out train.jsonl",
            file=sys.stderr,
        )
        sys.exit(1)

    can_stratify = len(classes) > 1 and all(y.count(c) >= 2 for c in classes)
    if can_stratify:
        stratify = y
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=args.test_size, random_state=42, stratify=stratify
        )
    else:
        X_train, y_train = X, y
        X_test, y_test = [], []

    n_pos = sum(1 for v in y_train if v == 1)
    n_neg = sum(1 for v in y_train if v == 0)
    print(f"Class distribution: {n_neg} good, {n_pos} bad")

    imbalance_strategy = "none"
    if args.balance and n_pos > 0 and n_neg > 0 and n_pos != n_neg:
        from sklearn.utils import resample
        imbalance_strategy = "oversample"
        X_arr = [list(x) for x in X_train]
        y_arr = list(y_train)
        pos_idx = [i for i, v in enumerate(y_arr) if v == 1]
        neg_idx = [i for i, v in enumerate(y_arr) if v == 0]
        if n_pos < n_neg:
            pos_X = [X_arr[i] for i in pos_idx]
            pos_y = [y_arr[i] for i in pos_idx]
            pos_X, pos_y = resample(pos_X, pos_y, n_samples=n_neg, random_state=42, replace=True)
            X_train = [X_arr[i] for i in neg_idx] + pos_X
            y_train = [y_arr[i] for i in neg_idx] + pos_y
        else:
            neg_X = [X_arr[i] for i in neg_idx]
            neg_y = [y_arr[i] for i in neg_idx]
            neg_X, neg_y = resample(neg_X, neg_y, n_samples=n_pos, random_state=42, replace=True)
            X_train = neg_X + [X_arr[i] for i in pos_idx]
            y_train = neg_y + [y_arr[i] for i in pos_idx]
        print(f"After balancing: {sum(1 for v in y_train if v == 0)} good, {sum(1 for v in y_train if v == 1)} bad")
    elif args.balance_class_weight:
        imbalance_strategy = "scale_pos_weight"

    n_pos_tr = sum(1 for v in y_train if v == 1)
    n_neg_tr = sum(1 for v in y_train if v == 0)
    if (args.balance or args.balance_class_weight) and n_pos_tr > 0 and n_neg_tr > 0:
        scale_pos_weight = float(n_neg_tr) / float(n_pos_tr)
    else:
        scale_pos_weight = 1.0

    xgb_kw = {**XGBOOST_PARAMS, "scale_pos_weight": scale_pos_weight}
    base_model = xgb.XGBClassifier(**xgb_kw)

    if do_calibrate:
        model = CalibratedClassifierCV(base_model, method="sigmoid", cv=3)
    else:
        model = base_model

    model.fit(X_train, y_train)

    metrics = {}
    if X_test and y_test:
        y_pred = model.predict(X_test)
        y_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else y_pred
        acc = accuracy_score(y_test, y_pred)
        metrics["accuracy"] = round(float(acc), 4)
        metrics["precision"] = round(float(precision_score(y_test, y_pred, zero_division=0)), 4)
        metrics["recall"] = round(float(recall_score(y_test, y_pred, zero_division=0)), 4)
        if len(set(y_test)) > 1:
            try:
                auc = roc_auc_score(y_test, y_proba)
                metrics["roc_auc"] = round(float(auc), 4)
            except Exception:
                pass
        print(f"Accuracy: {acc:.2%}")
        print(classification_report(y_test, y_pred, target_names=["good", "bad"], labels=[0, 1], zero_division=0))
        if "roc_auc" in metrics:
            print(f"ROC AUC: {metrics['roc_auc']:.3f}")
    else:
        print("Trained on all data (no test split; add more samples for evaluation)")

    out_path = Path(args.output)
    out_dir = Path(args.output_dir) if args.output_dir else out_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    model_path = out_dir / "model.pkl" if args.output_dir else out_path
    joblib.dump(model, model_path)
    joblib.dump(FEATURE_KEYS, out_dir / "feature_keys.pkl")

    metadata = {
        "model_type": "xgboost" + ("_calibrated" if do_calibrate else ""),
        "feature_keys": FEATURE_KEYS,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "training_date": datetime.utcnow().isoformat() + "Z",
        "dataset_size": len(rows),
        "class_distribution": {"good": n_neg, "bad": n_pos},
        "imbalance_strategy": imbalance_strategy,
        "xgboost_params": {k: v for k, v in xgb_kw.items() if k != "scale_pos_weight"},
        "scale_pos_weight": round(scale_pos_weight, 6),
        "metrics": metrics,
    }
    with open(out_dir / "metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"Model saved to {model_path}")
    print(f"Metadata saved to {out_dir / 'metadata.json'}")


if __name__ == "__main__":
    main()
