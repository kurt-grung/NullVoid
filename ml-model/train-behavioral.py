#!/usr/bin/env python3
"""
Train an XGBoost model for behavioral anomaly scoring (package scripts).
Reads JSONL from --input, outputs behavioral.model.json, behavioral.calib.json, behavioral-metadata.json.

Usage:
  python train-behavioral.py --input train-behavioral.jsonl
  python train-behavioral.py --input train-behavioral.jsonl --balance --calibrate
  python train-behavioral.py --input train-behavioral.jsonl --balance-class-weight --calibrate
"""

import argparse

import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

from train_common import drop_scanner_labelled_rows, train_and_save


_MANIFEST_PATH = Path(__file__).parent / "feature-keys.json"
_manifest = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
BEHAVIORAL_FEATURE_KEYS: List[str] = _manifest["behavioral"]
FEATURE_SCHEMA_VERSION = int(_manifest.get("version", 1))

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
    return [float(feats.get(k, 0)) for k in BEHAVIORAL_FEATURE_KEYS]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", "-i", help="Input JSONL file (train-behavioral.jsonl)")
    ap.add_argument("--output-dir", "-o", default=".", help="Output directory")
    ap.add_argument("--test-size", type=float, default=0.2, help="Test set fraction")
    ap.add_argument("--balance", action="store_true", help="Balance classes (oversample minority)")
    ap.add_argument(
        "--balance-class-weight",
        action="store_true",
        help="Balance via XGBoost scale_pos_weight only (no oversampling). Mutually exclusive with --balance.",
    )
    ap.add_argument("--calibrate", action="store_true", default=True, help="Apply Platt scaling")
    ap.add_argument("--no-calibrate", action="store_true", help="Disable calibration")
    ap.add_argument("--allow-scanner-labels", action="store_true", help="Keep rows labelled by the scanner itself (source scanner-*)")
    args = ap.parse_args()

    do_calibrate = args.calibrate and not args.no_calibrate

    rows = load_jsonl(args.input)
    if not rows:
        print(
            "No data. Run: node export-behavioral-features.js --from-ghsa --good-file benign-packages.txt --out train-behavioral.jsonl",
            file=sys.stderr,
        )
        sys.exit(1)

    rows = drop_scanner_labelled_rows(rows, args.allow_scanner_labels)
    X = [extract_features(r) for r in rows]
    y = [int(r.get("label", 0)) for r in rows]

    train_and_save(
        rows=rows,
        X=X,
        y=y,
        feature_keys=BEHAVIORAL_FEATURE_KEYS,
        schema_version=FEATURE_SCHEMA_VERSION,
        out_dir=Path(args.output_dir),
        name="behavioral",
        model_type="xgboost_behavioral",
        xgboost_params=XGBOOST_PARAMS,
        heldout_fraction=args.test_size,
        balance=args.balance,
        balance_class_weight=args.balance_class_weight,
        calibrate=do_calibrate,
    )


if __name__ == "__main__":
    main()
