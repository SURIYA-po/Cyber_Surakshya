"""Derive simulation attack profiles from the real training data.

    data/cicids2017_cleaned.csv ──► artifacts/attack_profiles.json

WHY THIS EXISTS
---------------
``app.py`` used to carry six hand-written ``ATTACK_PROFILES`` dictionaries.
Each supplied between 16 and 55 feature names against a model that needs 42
specific ones, so every profile was partly zero-filled before it reached the
classifier -- and several supplied features the model does not use at all
(``SYN Flag Count``, ``URG Flag Count``). The demo was therefore scoring
fabricated vectors, which is the exact failure mode the ingestion layer's
strict FlowNormalizer exists to prevent.

A per-class median over real labelled flows is representative by construction,
covers all 42 features, and needs no guessing about what a port scan "looks
like" numerically.

MEDIAN, NOT MEAN
----------------
These features are heavily skewed -- ``Flow Bytes/s`` spans zero to 1e9 and the
dataset replaces infinities with the column median. A mean would be dragged to
a value no real flow ever takes; a median is an actual point in the class.

Usage:
    python scripts/build_attack_profiles.py
    python scripts/build_attack_profiles.py --rows-per-class 100000
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd

BASE_DIR = Path(__file__).resolve().parents[1]
DEFAULT_DATASET = BASE_DIR / "data" / "cicids2017_cleaned.csv"
DEFAULT_FEATURES = BASE_DIR / "artifacts" / "feature_columns.json"
DEFAULT_OUTPUT = BASE_DIR / "artifacts" / "attack_profiles.json"

LABEL_COLUMN = "Attack Type"

# Matches preprocess.LABEL_MAP. Restated rather than imported so this script
# stays runnable without importing the training pipeline's dependencies.
LABEL_MAP: dict[str, str] = {
    "Normal Traffic": "BENIGN",
    "DoS":            "DOS",
    "DDoS":           "DDOS",
    "Port Scanning":  "PORTSCAN",
    "Brute Force":    "BRUTEFORCE",
    "Web Attacks":    "WEBATTACK",
    "Bots":           "BOTNET",
}

# The dataset header carries a typo in its first column: `pyDestination Port`.
# The values are genuine destination ports and the scaler is positional, so
# training was unaffected -- but `artifacts/feature_columns.json` was corrected
# to the canonical name, and name-based lookup here must follow.
COLUMN_FIXES: dict[str, str] = {"pyDestination Port": "Destination Port"}

# Enough rows for a stable median without holding 2.5M rows in memory.
DEFAULT_ROWS_PER_CLASS = 50_000
CHUNK_SIZE = 200_000


def load_feature_columns(path: Path) -> list[str]:
    with open(path, encoding="utf-8") as handle:
        columns = json.load(handle)
    if not isinstance(columns, list) or not columns:
        raise SystemExit(f"{path} does not contain a non-empty list.")
    return [str(c).strip() for c in columns]


def sample_rows_per_class(
    dataset: Path,
    feature_columns: list[str],
    rows_per_class: int,
) -> dict[str, pd.DataFrame]:
    """Stream the dataset, keeping a bounded sample of each class."""
    buckets: dict[str, list[pd.DataFrame]] = {}
    kept: dict[str, int] = {}

    reader = pd.read_csv(
        dataset,
        chunksize=CHUNK_SIZE,
        low_memory=False,
        encoding="utf-8",
        encoding_errors="replace",
    )

    for index, chunk in enumerate(reader):
        chunk.columns = chunk.columns.str.strip()
        chunk = chunk.rename(columns=COLUMN_FIXES)

        missing = [c for c in feature_columns if c not in chunk.columns]
        if missing:
            raise SystemExit(
                f"Dataset is missing {len(missing)} model feature(s): "
                f"{missing[:5]}. The artifacts and the dataset disagree."
            )

        chunk["__label__"] = chunk[LABEL_COLUMN].astype(str).str.strip().map(LABEL_MAP)
        chunk = chunk[chunk["__label__"].notna()]

        for label, group in chunk.groupby("__label__"):
            already = kept.get(label, 0)
            if already >= rows_per_class:
                continue
            take = group.head(rows_per_class - already)[feature_columns]
            buckets.setdefault(label, []).append(take)
            kept[label] = already + len(take)

        print(
            f"  chunk {index + 1}: "
            + ", ".join(f"{k}={v:,}" for k, v in sorted(kept.items())),
            flush=True,
        )
        if kept and all(v >= rows_per_class for v in kept.values()) and len(kept) >= 7:
            print("  all classes saturated; stopping early.")
            break

    return {label: pd.concat(frames, ignore_index=True) for label, frames in buckets.items()}


def build_profiles(
    samples: dict[str, pd.DataFrame],
    feature_columns: list[str],
) -> dict[str, dict[str, float]]:
    """Median feature vector per class, covering every model feature."""
    profiles: dict[str, dict[str, float]] = {}
    for label, frame in sorted(samples.items()):
        numeric = frame[feature_columns].apply(pd.to_numeric, errors="coerce")
        numeric = numeric.replace([np.inf, -np.inf], np.nan)
        medians = numeric.median(skipna=True).fillna(0.0)

        profile = {name: float(round(float(medians[name]), 6)) for name in feature_columns}
        missing = [n for n in feature_columns if n not in profile]
        if missing:
            raise SystemExit(f"{label}: profile missing {missing}")
        profiles[label] = profile
        print(f"  {label:<12s} rows={len(frame):>7,}  features={len(profile)}")
    return profiles


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--features", type=Path, default=DEFAULT_FEATURES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--rows-per-class", type=int, default=DEFAULT_ROWS_PER_CLASS)
    args = parser.parse_args()

    if not args.dataset.exists():
        raise SystemExit(
            f"Dataset not found: {args.dataset}\n"
            "This script needs the cleaned CICIDS2017 CSV used for training."
        )

    feature_columns = load_feature_columns(args.features)
    print(f"[PROFILES] Model features : {len(feature_columns)}")
    print(f"[PROFILES] Dataset        : {args.dataset}")
    print(f"[PROFILES] Rows per class : {args.rows_per_class:,}")

    print("[PROFILES] Sampling...")
    samples = sample_rows_per_class(args.dataset, feature_columns, args.rows_per_class)
    if not samples:
        raise SystemExit("No labelled rows matched LABEL_MAP.")

    print("[PROFILES] Computing medians...")
    profiles = build_profiles(samples, feature_columns)

    payload = {
        "_generated_by": "scripts/build_attack_profiles.py",
        "_source_dataset": os.path.basename(str(args.dataset)),
        "_rows_per_class": args.rows_per_class,
        "_statistic": "median",
        "_feature_count": len(feature_columns),
        "profiles": profiles,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)

    print(f"[PROFILES] Wrote {len(profiles)} profiles -> {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
