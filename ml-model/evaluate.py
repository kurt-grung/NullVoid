#!/usr/bin/env python3
"""
Evaluate a trained dependency-confusion model on a JSONL dataset.

Loads feature key order from feature_keys.pkl (same directory as --model unless --keys is set).
Prints accuracy, precision, recall, and ROC-AUC when both classes are present.

Usage:
  python evaluate.py --input train.jsonl --model model.pkl
  python evaluate.py --input train.jsonl --model /tmp/model.pkl --keys /tmp/feature_keys.pkl
"""

import argparse
import json
import sys
import warnings
from pathlib import Path
from typing import Any, Dict, List

import joblib

try:
    from sklearn.exceptions import InconsistentVersionWarning
except ImportError:
    InconsistentVersionWarning = None  # type: ignore[misc,assignment]

try:
    from sklearn.metrics import (
        accuracy_score,
        classification_report,
        precision_score,
        recall_score,
        roc_auc_score,
    )
except ImportError as e:
    print("Install: pip install scikit-learn joblib", file=sys.stderr)
    raise e

# Pickles may come from CI (newer sklearn); local older sklearn still evaluates correctly.
if InconsistentVersionWarning is not None:
    warnings.filterwarnings("ignore", category=InconsistentVersionWarning)


def load_jsonl(path: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    p = Path(path)
    if not p.exists():
        print(f"Input not found: {path}", file=sys.stderr)
        sys.exit(1)
    with open(p) as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def extract_features(row: Dict[str, Any], keys: List[str]) -> List[float]:
    feats = row.get("features", row)
    return [float(feats.get(k, 0)) for k in keys]


def main() -> None:
    ap = argparse.ArgumentParser(description="Evaluate NullVoid dependency model on JSONL")
    ap.add_argument("--input", "-i", required=True, help="JSONL with features and label")
    ap.add_argument("--model", "-m", default="model.pkl", help="Trained model (joblib)")
    ap.add_argument(
        "--keys",
        "-k",
        help="feature_keys.pkl path (default: same directory as model)",
    )
    ap.add_argument("--json", action="store_true", help="Print single-line JSON metrics to stdout")
    args = ap.parse_args()

    model_path = Path(args.model)
    if not model_path.is_file():
        print(f"Model not found: {model_path}", file=sys.stderr)
        sys.exit(1)

    keys_path = Path(args.keys) if args.keys else model_path.parent / "feature_keys.pkl"
    if not keys_path.is_file():
        print(f"feature_keys.pkl not found: {keys_path}", file=sys.stderr)
        sys.exit(1)

    model = joblib.load(model_path)
    feature_keys: List[str] = joblib.load(keys_path)

    rows = load_jsonl(args.input)
    if not rows:
        print("No rows in input.", file=sys.stderr)
        sys.exit(1)

    X = [extract_features(r, feature_keys) for r in rows]
    y = [int(r.get("label", 0)) for r in rows]

    y_pred = model.predict(X)
    y_proba = None
    if hasattr(model, "predict_proba"):
        y_proba = model.predict_proba(X)[:, 1]

    acc = float(accuracy_score(y, y_pred))
    prec = float(precision_score(y, y_pred, zero_division=0))
    rec = float(recall_score(y, y_pred, zero_division=0))
    roc = None
    if y_proba is not None and len(set(y)) > 1:
        try:
            roc = float(roc_auc_score(y, y_proba))
        except ValueError:
            pass

    metrics = {
        "samples": len(rows),
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
    }
    if roc is not None:
        metrics["roc_auc"] = round(roc, 4)

    if args.json:
        print(json.dumps(metrics))
    else:
        print(f"Samples: {metrics['samples']}")
        print(f"Accuracy:  {acc:.2%}")
        print(f"Precision: {prec:.4f}")
        print(f"Recall:    {rec:.4f}")
        if roc is not None:
            print(f"ROC AUC:   {roc:.4f}")
        print(classification_report(y, y_pred, target_names=["good", "bad"], labels=[0, 1], zero_division=0))


if __name__ == "__main__":
    main()
