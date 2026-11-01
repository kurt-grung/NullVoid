#!/usr/bin/env python3
"""
Train a lightweight ensemble model that stacks dependency and behavioral scores.

Usage:
  python train-ensemble.py --input train.jsonl
"""

import argparse
import json
from datetime import datetime
from pathlib import Path

import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    if not path.exists():
        return rows
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="train.jsonl", help="Input JSONL with labels and feature vectors")
    ap.add_argument("--dep-model", default="model.pkl", help="Dependency model path")
    ap.add_argument("--beh-model", default="behavioral-model.pkl", help="Behavioral model path")
    ap.add_argument("--output", default="ensemble-model.pkl", help="Output ensemble model path")
    ap.add_argument("--metadata", default="ensemble-metadata.json", help="Output metadata path")
    ap.add_argument("--test-size", type=float, default=0.2, help="Fraction of data held out for evaluation")
    args = ap.parse_args()

    rows = load_jsonl(Path(args.input))
    if not rows:
        raise SystemExit("No rows found in input JSONL")

    dep_model = joblib.load(args.dep_model)
    beh_model = joblib.load(args.beh_model)
    dep_keys = joblib.load("feature_keys.pkl")
    beh_keys = joblib.load("behavioral-feature_keys.pkl")

    X = []
    y = []
    for row in rows:
        feats = row.get("features", row)
        label = int(row.get("label", 0))
        dep_vec = [float(feats.get(k, 0)) for k in dep_keys]
        beh_vec = [float(feats.get(k, 0)) for k in beh_keys]
        dep_proba = dep_model.predict_proba([dep_vec])[0]
        beh_proba = beh_model.predict_proba([beh_vec])[0]
        dep_bad = float(dep_proba[1] if len(dep_proba) > 1 else dep_proba[0])
        beh_bad = float(beh_proba[1] if len(beh_proba) > 1 else beh_proba[0])
        X.append([dep_bad, beh_bad])
        y.append(label)

    if len(set(y)) < 2:
        raise SystemExit("Ensemble training requires both classes")

    # Use a stratified train/test split so reported metrics are on held-out data.
    use_split = len(rows) >= 20 and args.test_size > 0
    if use_split:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=args.test_size, random_state=42, stratify=y
        )
    else:
        X_train, y_train = X, y
        X_test, y_test = X, y

    ensemble = LogisticRegression(random_state=42)
    ensemble.fit(X_train, y_train)

    preds = ensemble.predict(X_test)
    probas = ensemble.predict_proba(X_test)[:, 1]

    joblib.dump(ensemble, args.output)
    metadata = {
        "model_type": "logreg_stacker",
        "training_date": datetime.utcnow().isoformat() + "Z",
        "dataset_size": len(rows),
        "train_size": len(X_train),
        "test_size": len(X_test),
        "eval_on_holdout": use_split,
        "input_features": ["dependency_score", "behavioral_score"],
        "metrics": {
            "accuracy": round(float(accuracy_score(y_test, preds)), 4),
            "precision": round(float(precision_score(y_test, preds, zero_division=0)), 4),
            "recall": round(float(recall_score(y_test, preds, zero_division=0)), 4),
            "roc_auc": round(float(roc_auc_score(y_test, probas)), 4),
        },
        "dep_model": args.dep_model,
        "beh_model": args.beh_model,
    }
    with open(args.metadata, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"Ensemble model saved to {args.output}")
    print(f"Metadata saved to {args.metadata}")
    print(f"Eval on {'held-out test set' if use_split else 'training data (insufficient data for split)'}: "
          f"accuracy={metadata['metrics']['accuracy']}, roc_auc={metadata['metrics']['roc_auc']}")


if __name__ == "__main__":
    main()
