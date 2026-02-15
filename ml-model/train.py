#!/usr/bin/env python3
"""
Train a logistic regression model for dependency confusion threat scoring.
Reads JSONL from stdin or --input, outputs model.pkl and metrics.

Usage:
  python train.py --input train.jsonl
  cat train.jsonl | python train.py
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

try:
    import joblib
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, classification_report, roc_auc_score
except ImportError:
    print("Install: pip install scikit-learn joblib", file=sys.stderr)
    sys.exit(1)

FEATURE_KEYS = [
    "daysDifference",
    "recentCommitCount",
    "scopePrivate",
    "suspiciousPatternsCount",
    "timelineAnomaly",
    "registryIsNpm",
    "authorCount",
    "totalCommitCount",
    "dominantAuthorShare",
    "commitPatternAnomaly",
    "branchCount",
    "recentCommitCount90d",
    "messageAnomalyScore",
    "diffAnomalyScore",
    "nlpSecurityScore",
    "nlpSuspiciousCount",
    "crossPackageAnomaly",
    "behavioralAnomaly",
    "reviewSecurityScore",
    "popularityScore",
    "trustScore",
]


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
    ap.add_argument("--test-size", type=float, default=0.2, help="Test set fraction")
    args = ap.parse_args()

    rows = load_jsonl(args.input)
    if not rows:
        print("No data. Provide --input or pipe JSONL.", file=sys.stderr)
        sys.exit(1)

    X = [extract_features(r) for r in rows]
    y = [int(r.get("label", 0)) for r in rows]

    can_stratify = len(set(y)) > 1 and all(y.count(c) >= 2 for c in set(y))
    stratify = y if can_stratify else None
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=42, stratify=stratify
    )

    model = LogisticRegression(max_iter=1000, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"Accuracy: {acc:.2%}")
    print(classification_report(y_test, y_pred, target_names=["good", "bad"], labels=[0, 1], zero_division=0))

    if len(set(y_test)) > 1:
        try:
            auc = roc_auc_score(y_test, model.predict_proba(X_test)[:, 1])
            print(f"ROC AUC: {auc:.3f}")
        except Exception:
            pass

    joblib.dump(model, args.output)
    joblib.dump(FEATURE_KEYS, "feature_keys.pkl")
    print(f"Model saved to {args.output}")


if __name__ == "__main__":
    main()
