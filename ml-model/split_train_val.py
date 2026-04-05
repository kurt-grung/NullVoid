#!/usr/bin/env python3
"""
Split a JSONL dataset (features + label) into train and validation files.

Uses stratified splitting when each class has at least 2 samples; otherwise
random split. Fails if the dataset is too small to form both splits.

Usage:
  python split_train_val.py --input train.jsonl --train-out /tmp/train.jsonl --val-out /tmp/val.jsonl
  python split_train_val.py -i train.jsonl --train-out a.jsonl --val-out b.jsonl --val-fraction 0.2 --seed 42
  python split_train_val.py -i train.jsonl --train-out tr.jsonl --val-out va.jsonl --time-val-newest --time-field exportedAt
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from sklearn.model_selection import train_test_split
except ImportError as e:
    print("Install: pip install scikit-learn", file=sys.stderr)
    raise e


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r, separators=(",", ":")) + "\n")


def _parse_iso_ts(value: Any) -> Optional[datetime]:
    if value is None or not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def time_based_split(
    rows: List[Dict[str, Any]], val_fraction: float, time_field: str
) -> Optional[Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]]:
    """Oldest (train) / newest (val) split when every row has a parseable time_field."""
    keyed: List[Tuple[datetime, int, Dict[str, Any]]] = []
    for i, r in enumerate(rows):
        ts = _parse_iso_ts(r.get(time_field))
        if ts is None:
            return None
        keyed.append((ts, i, r))
    keyed.sort(key=lambda t: (t[0], t[1]))
    ordered = [t[2] for t in keyed]
    n = len(ordered)
    n_val = max(1, min(n - 1, int(round(n * val_fraction))))
    if n_val >= n:
        return None
    val_rows = ordered[-n_val:]
    train_rows = ordered[:-n_val]
    return train_rows, val_rows


def main() -> None:
    ap = argparse.ArgumentParser(description="Stratified train/val split for ML JSONL")
    ap.add_argument("--input", "-i", required=True, help="Input JSONL path")
    ap.add_argument("--train-out", required=True, help="Output path for training rows")
    ap.add_argument("--val-out", required=True, help="Output path for validation rows")
    ap.add_argument(
        "--val-fraction",
        type=float,
        default=0.2,
        help="Fraction of rows for validation (default 0.2)",
    )
    ap.add_argument("--seed", type=int, default=42, help="Random seed")
    ap.add_argument(
        "--time-val-newest",
        action="store_true",
        help="If every row has --time-field (ISO-8601), put the newest val_fraction rows in validation",
    )
    ap.add_argument(
        "--time-field",
        default="exportedAt",
        help="Row field for time-based split (default: exportedAt)",
    )
    args = ap.parse_args()

    inp = Path(args.input)
    if not inp.is_file():
        print(f"Input not found: {inp}", file=sys.stderr)
        sys.exit(1)

    rows = load_jsonl(inp)
    if len(rows) < 4:
        print("Need at least 4 rows to split into train and validation.", file=sys.stderr)
        sys.exit(1)

    if not (0 < args.val_fraction < 1):
        print("--val-fraction must be between 0 and 1.", file=sys.stderr)
        sys.exit(1)

    split_mode = "stratified"
    train_rows: List[Dict[str, Any]]
    val_rows: List[Dict[str, Any]]
    can_stratify = False

    if args.time_val_newest:
        tb = time_based_split(rows, args.val_fraction, args.time_field)
        if tb is not None:
            train_rows, val_rows = tb
            split_mode = "time_newest_val"
        else:
            print(
                json.dumps(
                    {
                        "time_split_skipped": True,
                        "reason": f"Not all rows have a parseable {args.time_field!r}; using random/stratified split.",
                    }
                ),
                file=sys.stderr,
            )

    if split_mode == "stratified":
        indices = list(range(len(rows)))
        y = [int(rows[i].get("label", 0)) for i in indices]
        classes = set(y)
        can_stratify = len(classes) > 1 and all(y.count(c) >= 2 for c in classes)

        stratify = y if can_stratify else None
        train_idx, val_idx = train_test_split(
            indices,
            test_size=args.val_fraction,
            random_state=args.seed,
            stratify=stratify,
        )

        train_rows = [rows[i] for i in train_idx]
        val_rows = [rows[i] for i in val_idx]

    if not train_rows or not val_rows:
        print("Split produced an empty train or validation set.", file=sys.stderr)
        sys.exit(1)

    write_jsonl(Path(args.train_out), train_rows)
    write_jsonl(Path(args.val_out), val_rows)

    yt = [int(r.get("label", 0)) for r in train_rows]
    yv = [int(r.get("label", 0)) for r in val_rows]
    print(
        json.dumps(
            {
                "total": len(rows),
                "train": len(train_rows),
                "val": len(val_rows),
                "train_labels": {"good": sum(1 for v in yt if v == 0), "bad": sum(1 for v in yt if v == 1)},
                "val_labels": {"good": sum(1 for v in yv if v == 0), "bad": sum(1 for v in yv if v == 1)},
                "stratified": can_stratify if split_mode != "time_newest_val" else False,
                "split_mode": split_mode,
            }
        )
    )


if __name__ == "__main__":
    main()
