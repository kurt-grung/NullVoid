#!/usr/bin/env python3
"""
Gate on the held-out metrics recorded in a model's metadata.

    python3 check_metrics.py --metadata metadata.json --min-roc-auc 0.9 --min-pr-auc 0.5
    python3 check_metrics.py --metadata metadata.json --baseline <(git show HEAD:ml-model/metadata.json) --max-regression 0.05

Fails (exit 1) when:
  * metrics are missing or empty — a model that was never evaluated is not shippable;
  * any --min-* floor is not met;
  * --baseline is given and roc_auc or pr_auc dropped by more than --max-regression
    against the baseline metadata (a retrain made the model worse).

Prints a one-line JSON summary on stdout so CI logs show the numbers.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List


def load(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--metadata", required=True, help="metadata.json written by train.py / train-behavioral.py")
    ap.add_argument("--baseline", help="Previous metadata.json to compare against (regression check)")
    ap.add_argument("--max-regression", type=float, default=0.05, help="Allowed drop in roc_auc / pr_auc vs baseline")
    ap.add_argument("--min-roc-auc", type=float, default=0.0)
    ap.add_argument("--min-pr-auc", type=float, default=0.0)
    ap.add_argument("--min-precision", type=float, default=0.0)
    ap.add_argument("--min-recall", type=float, default=0.0)
    ap.add_argument("--min-positives", type=int, default=10, help="Held-out set must contain at least this many positives")
    args = ap.parse_args()

    meta = load(args.metadata)
    metrics = meta.get("metrics") or {}
    failures: List[str] = []

    required = ("precision", "recall", "roc_auc", "pr_auc")
    missing = [k for k in required if metrics.get(k) is None]
    if not metrics or missing:
        failures.append(f"metrics missing or incomplete ({', '.join(missing) or 'empty'}); the model was not evaluated on a held-out set")
    else:
        if int(metrics.get("positives", 0)) < args.min_positives:
            failures.append(f"held-out set has {metrics.get('positives', 0)} positives (< {args.min_positives})")
        for key, floor in (
            ("roc_auc", args.min_roc_auc),
            ("pr_auc", args.min_pr_auc),
            ("precision", args.min_precision),
            ("recall", args.min_recall),
        ):
            if float(metrics[key]) < floor:
                failures.append(f"{key} {metrics[key]} < required {floor}")

        if args.baseline and Path(args.baseline).exists():
            base = (load(args.baseline).get("metrics") or {})
            for key in ("roc_auc", "pr_auc"):
                if base.get(key) is not None and metrics.get(key) is not None:
                    drop = float(base[key]) - float(metrics[key])
                    if drop > args.max_regression:
                        failures.append(f"{key} regressed {base[key]} -> {metrics[key]} (drop {drop:.4f} > {args.max_regression})")

    summary = {
        "metadata": args.metadata,
        "metrics": {k: metrics.get(k) for k in ("samples", "positives", "precision", "recall", "f1", "roc_auc", "pr_auc", "brier")},
        "split": (meta.get("split") or {}).get("method"),
        "ok": not failures,
        "failures": failures,
    }
    print(json.dumps(summary))
    if failures:
        for f in failures:
            print(f"metrics gate: {f}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
