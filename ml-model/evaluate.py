#!/usr/bin/env python3
"""
Evaluate a trained NullVoid ML model on a JSONL dataset (dependency or behavioral).

Loads the JSON model artifacts (model_io) and their feature key order
(behavioral).

Metrics (JSON): samples, accuracy, precision, recall, optional roc_auc, optional brier
(mean squared error of predicted probability vs label).

Held-out evaluation: use split_train_val.py to build a validation JSONL, train on the
train split only, then run evaluate.py on the validation file. CI uses this pattern.

Optional quality gates (exit 1 if unmet, only when the metric is defined):
  --min-roc-auc 0.5
  --min-precision 0.0
  --min-recall 0.0
When the eval set has no label-1 (bad) rows, --min-precision and --min-recall are skipped
(precision/recall for detecting bad are degenerate), and JSON output may include
precision_recall_gates_skipped: true.

Usage:
  python evaluate.py --input train.jsonl --model .
  python evaluate.py --input val.jsonl --model /tmp/out --json
  python evaluate.py --behavioral --input val.jsonl --model . --json
"""

from __future__ import annotations

import argparse
import json
import sys
import warnings
from pathlib import Path
from typing import Any, Dict, List, Optional

from model_io import ModelIntegrityError, load_model

try:
    from sklearn.exceptions import InconsistentVersionWarning
except ImportError:
    InconsistentVersionWarning = None  # type: ignore[misc,assignment]

try:
    from sklearn.metrics import (
        accuracy_score,
        brier_score_loss,
        classification_report,
        precision_score,
        recall_score,
        roc_auc_score,
    )
except ImportError as e:
    print("Install: pip install scikit-learn xgboost", file=sys.stderr)
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
    ap = argparse.ArgumentParser(description="Evaluate NullVoid ML model on JSONL")
    ap.add_argument("--input", "-i", required=True, help="JSONL with features and label")
    ap.add_argument(
        "--model",
        "-m",
        default=None,
        help="Directory with model.model.json / behavioral.model.json (default: .)",
    )
    ap.add_argument(
        "--behavioral",
        action="store_true",
        help="Evaluate the behavioral model (behavioral.model.json) from the model directory",
    )
    ap.add_argument("--json", action="store_true", help="Print single-line JSON metrics to stdout")
    ap.add_argument(
        "--eval-set",
        default="full",
        help="Label embedded in JSON output, e.g. validation, train_fit, full (default: full)",
    )
    ap.add_argument(
        "--min-roc-auc",
        type=float,
        default=None,
        help="If set and roc_auc is computed, exit 1 when below this threshold",
    )
    ap.add_argument(
        "--min-precision",
        type=float,
        default=None,
        help="If set, exit 1 when precision is below this threshold",
    )
    ap.add_argument(
        "--min-recall",
        type=float,
        default=None,
        help="If set, exit 1 when recall is below this threshold",
    )
    args = ap.parse_args()

    # --model may be a directory holding the JSON artifacts, or the
    # model.model.json / behavioral.model.json file itself.
    name = "behavioral" if args.behavioral else "model"
    model_arg = Path(args.model) if args.model else Path(".")
    model_dir = model_arg if model_arg.is_dir() else model_arg.parent
    if (model_dir / f"{name}.model.json").is_file() is False:
        print(f"Model not found: {model_dir / f'{name}.model.json'}", file=sys.stderr)
        sys.exit(1)
    try:
        model, _meta = load_model(model_dir, name)
    except ModelIntegrityError as e:
        print(f"Refusing to load model: {e}", file=sys.stderr)
        sys.exit(2)
    feature_keys: List[str] = model.feature_keys

    rows = load_jsonl(args.input)
    if not rows:
        print("No rows in input.", file=sys.stderr)
        sys.exit(1)

    X = [extract_features(r, feature_keys) for r in rows]
    y = [int(r.get("label", 0)) for r in rows]
    # Precision/recall gates target detection of label 1 (bad). If the eval slice has no bad
    # rows (e.g. time-based split put only good packages in validation), those metrics are
    # degenerate and should not fail CI.
    pr_gates_meaningful = 1 in y

    y_pred = model.predict(X)
    y_proba: Optional[Any] = None
    if hasattr(model, "predict_proba"):
        y_proba = model.predict_proba(X)[:, 1]

    acc = float(accuracy_score(y, y_pred))
    prec = float(precision_score(y, y_pred, zero_division=0))
    rec = float(recall_score(y, y_pred, zero_division=0))
    roc: Optional[float] = None
    brier: Optional[float] = None
    if y_proba is not None and len(set(y)) > 1:
        try:
            roc = float(roc_auc_score(y, y_proba))
        except ValueError:
            pass
        try:
            brier = float(brier_score_loss(y, y_proba))
        except ValueError:
            pass

    model_kind = "behavioral" if args.behavioral else "dependency"

    metrics: Dict[str, Any] = {
        "model": model_kind,
        "eval_set": args.eval_set,
        "samples": len(rows),
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
    }
    if roc is not None:
        metrics["roc_auc"] = round(roc, 4)
    if brier is not None:
        metrics["brier"] = round(brier, 4)
    if args.json and not pr_gates_meaningful and (
        args.min_precision is not None or args.min_recall is not None
    ):
        metrics["precision_recall_gates_skipped"] = True

    failed_gate = False
    if args.min_roc_auc is not None and roc is not None and roc < args.min_roc_auc:
        print(
            f"Gate failed: roc_auc {roc:.4f} < --min-roc-auc {args.min_roc_auc}",
            file=sys.stderr,
        )
        failed_gate = True
    if not pr_gates_meaningful and (
        args.min_precision is not None or args.min_recall is not None
    ):
        print(
            "Skipping --min-precision/--min-recall: eval set has no positive (bad) labels.",
            file=sys.stderr,
        )
    if args.min_precision is not None and pr_gates_meaningful and prec < args.min_precision:
        print(
            f"Gate failed: precision {prec:.4f} < --min-precision {args.min_precision}",
            file=sys.stderr,
        )
        failed_gate = True
    if args.min_recall is not None and pr_gates_meaningful and rec < args.min_recall:
        print(
            f"Gate failed: recall {rec:.4f} < --min-recall {args.min_recall}",
            file=sys.stderr,
        )
        failed_gate = True

    if args.json:
        print(json.dumps(metrics))

    if not args.json:
        print(f"Model:     {model_kind} ({model_path})")
        print(f"Eval set:  {args.eval_set}")
        print(f"Samples:   {metrics['samples']}")
        print(f"Accuracy:  {acc:.2%}")
        print(f"Precision: {prec:.4f}")
        print(f"Recall:    {rec:.4f}")
        if roc is not None:
            print(f"ROC AUC:   {roc:.4f}")
        if brier is not None:
            print(f"Brier:     {brier:.4f}")
        print(
            classification_report(
                y, y_pred, target_names=["good", "bad"], labels=[0, 1], zero_division=0
            )
        )

    if failed_gate:
        sys.exit(1)


if __name__ == "__main__":
    main()
