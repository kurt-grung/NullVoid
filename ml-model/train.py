#!/usr/bin/env python3
"""
Train an XGBoost model for dependency confusion threat scoring.
Reads JSONL from stdin or --input, outputs model.model.json, model.calib.json, metadata.json (see model_io.py).

Usage:
  python train.py --input train.jsonl --output-dir .
  python train.py --input train.jsonl --balance --calibrate
  python train.py --input train.jsonl --balance-class-weight --calibrate
  cat train.jsonl | python train.py

Held-out evaluation: the newest 20% of packages per class (by first publish
date) are scored before the shipped booster is refitted on all rows; the
metrics land in metadata.json (see train_common.py / dataset_split.py).
"""

import argparse

import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

from train_common import drop_scanner_labelled_rows, train_and_save


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
    ap.add_argument("--output-dir", "-o", default=".", help="Output directory (model.model.json, model.calib.json, metadata.json)")
    ap.add_argument("--output", help=argparse.SUPPRESS)  # legacy: a path whose parent directory is used
    ap.add_argument("--test-size", type=float, default=0.2, help="Held-out fraction (newest packages per class when rows carry `time`)")
    ap.add_argument("--no-refit", action="store_true", help="Ship the model trained on the train split instead of refitting on all rows")
    ap.add_argument("--allow-scanner-labels", action="store_true", help="Keep rows labelled by the scanner itself (source scanner-*)")
    ap.add_argument("--balance", action="store_true", help="Balance classes (oversample minority)")
    ap.add_argument(
        "--balance-class-weight",
        action="store_true",
        help="Balance via XGBoost scale_pos_weight only (no oversampling). Mutually exclusive with --balance.",
    )
    ap.add_argument("--calibrate", action="store_true", default=True, help="Apply Platt scaling for probability calibration (default: True)")
    ap.add_argument("--no-calibrate", action="store_true", help="Disable probability calibration")
    ap.add_argument("--tune", action="store_true", help="Tune XGBoost params with GridSearchCV before training")
    args = ap.parse_args()

    do_calibrate = args.calibrate and not args.no_calibrate

    rows = load_jsonl(args.input)
    if not rows:
        print("No data. Provide --input or pipe JSONL.", file=sys.stderr)
        sys.exit(1)

    rows = drop_scanner_labelled_rows(rows, args.allow_scanner_labels)
    X = [extract_features(r) for r in rows]
    y = [int(r.get("label", 0)) for r in rows]
    out_dir = Path(args.output).parent if args.output else Path(args.output_dir)

    train_and_save(
        rows=rows,
        X=X,
        y=y,
        feature_keys=FEATURE_KEYS,
        schema_version=FEATURE_SCHEMA_VERSION,
        out_dir=out_dir,
        name="model",
        model_type="xgboost",
        xgboost_params=XGBOOST_PARAMS,
        heldout_fraction=args.test_size,
        balance=args.balance,
        balance_class_weight=args.balance_class_weight,
        calibrate=do_calibrate,
        refit=not args.no_refit,
        tune=bool(args.tune),
    )


if __name__ == "__main__":
    main()
