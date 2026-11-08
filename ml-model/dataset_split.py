"""
Held-out evaluation helpers shared by train.py and train-behavioral.py.

Rows exported by export-features.js carry `time` (first publish, ISO 8601) and
`source`. When every row has a time, the held-out set is the newest fraction of
each class by first publish date ("time-stratified"): the model is scored on
packages published after the ones it learned from, per class, so the held-out
set still contains both classes even though malware rows are all recent and
benign rows are mostly old. Rows without a time fall back to a stratified
random split.
"""

from __future__ import annotations

import collections
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np


def _parse_time(value: Any) -> Optional[datetime]:
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _base_name(row: Dict[str, Any]) -> Optional[str]:
    """Package name without the `@+Nd` snapshot suffix, so a package and its
    early-life snapshots always land on the same side of the split."""
    name = row.get("name")
    if not isinstance(name, str):
        return None
    if "@+" in name and name.endswith("d"):
        return name[: name.rindex("@+")]
    return name


def time_stratified_split(
    rows: Sequence[Dict[str, Any]], y: Sequence[int], heldout_frac: float, seed: int = 42
) -> Tuple[List[int], List[int], Dict[str, Any]]:
    """Return (train_idx, test_idx, split_info)."""
    n = len(rows)
    times = [_parse_time(r.get("time")) for r in rows]
    have_time = all(t is not None for t in times) and n > 0

    if not have_time:
        from sklearn.model_selection import train_test_split

        idx = list(range(n))
        can_stratify = all(list(y).count(c) >= 2 for c in set(y))
        train_idx, test_idx = train_test_split(
            idx, test_size=heldout_frac, random_state=seed, stratify=list(y) if can_stratify else None
        )
        return list(train_idx), list(test_idx), {"method": "random-stratified", "heldout_fraction": heldout_frac}

    # Group by base package name: newest packages per class go to held-out.
    groups: Dict[Tuple[int, str], List[int]] = collections.defaultdict(list)
    for i, r in enumerate(rows):
        key = (int(y[i]), _base_name(r) or f"__row{i}")
        groups[key].append(i)

    train_idx: List[int] = []
    test_idx: List[int] = []
    cutoffs: Dict[str, str] = {}
    for label in sorted({int(v) for v in y}):
        keys = [k for k in groups if k[0] == label]
        keys.sort(key=lambda k: min(times[i] for i in groups[k]))  # type: ignore[type-var]
        n_test = max(1, int(round(len(keys) * heldout_frac))) if len(keys) >= 2 else 0
        split_at = len(keys) - n_test
        for j, k in enumerate(keys):
            (test_idx if j >= split_at else train_idx).extend(groups[k])
        if n_test:
            cutoffs[str(label)] = min(times[i] for i in groups[keys[split_at]]).isoformat()  # type: ignore[type-var]

    return train_idx, test_idx, {
        "method": "time-stratified",
        "heldout_fraction": heldout_frac,
        "grouping": "package (snapshots stay with their package)",
        "cutoff_first_publish": cutoffs,
    }


def heldout_metrics(y_true: Sequence[int], y_proba: Sequence[float], threshold: float = 0.5) -> Dict[str, Any]:
    from sklearn.metrics import (
        accuracy_score,
        average_precision_score,
        brier_score_loss,
        f1_score,
        precision_score,
        recall_score,
        roc_auc_score,
    )

    yt = np.asarray(y_true, dtype=int)
    yp = np.asarray(y_proba, dtype=float)
    pred = (yp >= threshold).astype(int)
    out: Dict[str, Any] = {
        "samples": int(len(yt)),
        "positives": int(yt.sum()),
        "threshold": threshold,
        "accuracy": round(float(accuracy_score(yt, pred)), 4),
        "precision": round(float(precision_score(yt, pred, zero_division=0)), 4),
        "recall": round(float(recall_score(yt, pred, zero_division=0)), 4),
        "f1": round(float(f1_score(yt, pred, zero_division=0)), 4),
        "brier": round(float(brier_score_loss(yt, yp)), 4),
    }
    if len(set(yt.tolist())) > 1:
        out["roc_auc"] = round(float(roc_auc_score(yt, yp)), 4)
        out["pr_auc"] = round(float(average_precision_score(yt, yp)), 4)
    return out


def dataset_summary(rows: Sequence[Dict[str, Any]], y: Sequence[int]) -> Dict[str, Any]:
    sources: Dict[str, Dict[str, int]] = collections.defaultdict(lambda: {"good": 0, "bad": 0})
    times = [t for t in (_parse_time(r.get("time")) for r in rows) if t is not None]
    for r, label in zip(rows, y):
        src = r.get("source") or "unknown"
        sources[src]["bad" if int(label) == 1 else "good"] += 1
    distinct = {_base_name(r) for r in rows if _base_name(r)}
    return {
        "rows": len(rows),
        "distinct_packages": len(distinct),
        "class_distribution": {"good": int(sum(1 for v in y if int(v) == 0)), "bad": int(sum(1 for v in y if int(v) == 1))},
        "sources": dict(sources),
        "first_publish_range": [min(times).isoformat(), max(times).isoformat()] if times else None,
        "labeling": "ground truth: GHSA malware advisories = 1, reviewed benign list = 0; never from scanner output",
    }
