"""Reconstruct artifacts/manifest.json from artifacts already on disk.

    artifacts/evaluation_report.txt ──► artifacts/manifest.json

WHY THIS EXISTS
---------------
`train.py` now writes a manifest naming the model to serve, but the artifacts
currently committed predate it. Retraining purely to produce a manifest would
take hours and would replace working, validated models. This reads the
per-class metrics out of the evaluation report the original run already
produced and records the same decision.

WHAT IT DECIDES
---------------
The served model is the one with the highest macro F1 whose weakest per-class
recall clears `MIN_CLASS_RECALL`. That matters here: three of the four models
in this project score >0.99 weighted F1 while catching 8-10% of WEBATTACK.
Selecting on the headline number would promote one of them.

Usage:
    python scripts/build_manifest.py
    python scripts/build_manifest.py --dry-run
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform as _platform
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
DEFAULT_ARTIFACT_DIR = BASE_DIR / "artifacts"
DEFAULT_DATASET = BASE_DIR / "data" / "cicids2017_cleaned.csv"

# Mirrors train.MIN_CLASS_RECALL. Restated so this script does not import the
# training pipeline (and its heavy dependencies) just to read one constant.
MIN_CLASS_RECALL = 0.50

# "=================================== DNN"
_MODEL_HEADER = re.compile(r"^=+\s+(\S+)\s*$")
# "      BENIGN       0.99      1.00      0.99     24000"
_CLASS_ROW = re.compile(
    r"^\s+(?P<cls>[A-Z][A-Z0-9_]*)\s+"
    r"(?P<precision>\d\.\d+)\s+(?P<recall>\d\.\d+)\s+"
    r"(?P<f1>\d\.\d+)\s+(?P<support>\d+)\s*$"
)
# "  RandomForest                0.9942    0.9924    0.9942      0.9944    0.9975"
_SUMMARY_ROW = re.compile(
    r"^\s{2}(?P<name>[A-Za-z][A-Za-z0-9_]*)\s+"
    r"(?P<accuracy>\d\.\d+)\s+(?P<f1w>\d\.\d+)\s+"
)


def parse_evaluation_report(path: Path) -> dict[str, dict]:
    """Extract per-model, per-class metrics from the training report."""
    text = path.read_text(encoding="utf-8", errors="replace")
    models: dict[str, dict] = {}

    current: str | None = None
    for line in text.splitlines():
        header = _MODEL_HEADER.match(line)
        if header and not line.strip("= ").startswith("CICIDS"):
            candidate = header.group(1)
            # Section headers such as "====== DNN" name a model; decorative
            # rules of pure '=' do not.
            if candidate and not set(candidate) <= {"="}:
                current = candidate
                models.setdefault(
                    current, {"per_class_recall": {}, "per_class_f1": {}}
                )
            continue

        if current:
            row = _CLASS_ROW.match(line)
            if row:
                cls = row.group("cls")
                models[current]["per_class_recall"][cls] = float(row.group("recall"))
                models[current]["per_class_f1"][cls] = float(row.group("f1"))

    # Accuracy and weighted F1 come from the summary table at the top.
    for line in text.splitlines():
        summary = _SUMMARY_ROW.match(line)
        if summary:
            name = summary.group("name")
            if name in models:
                models[name]["accuracy"] = float(summary.group("accuracy"))
                models[name]["f1_weighted"] = float(summary.group("f1w"))

    # Derive macro figures from the per-class values we parsed. Macro averages
    # weight every class equally, which is the whole point: they cannot be
    # propped up by the four classes that make up 99% of the rows.
    for m in models.values():
        recalls = m["per_class_recall"]
        f1s = m["per_class_f1"]
        if recalls:
            m["recall_macro"] = round(sum(recalls.values()) / len(recalls), 4)
            worst = min(recalls, key=recalls.get)
            m["min_class_recall"] = recalls[worst]
            m["worst_class"] = worst
        if f1s:
            m["f1_macro"] = round(sum(f1s.values()) / len(f1s), 4)

    return {n: m for n, m in models.items() if m.get("per_class_recall")}


def select_served_model(metrics: dict[str, dict], artifact_dir: Path) -> str:
    """Highest macro recall among models present on disk that clear the floor."""
    available = {
        name: m for name, m in metrics.items()
        if (artifact_dir / f"model_{name}.pkl").exists()
    }
    if not available:
        raise SystemExit(
            f"No model_<name>.pkl files in {artifact_dir} match the models in "
            "the evaluation report."
        )

    viable = {
        name: m for name, m in available.items()
        if m.get("min_class_recall", 0.0) >= MIN_CLASS_RECALL
    }
    rejected = sorted(set(available) - set(viable))
    if rejected:
        print(f"  Excluded (per-class recall < {MIN_CLASS_RECALL:.0%}):")
        for name in rejected:
            m = available[name]
            print(f"    {name:<20s} {m['worst_class']}={m['min_class_recall']:.2f}")

    if not viable:
        print("  [WARN] No model clears the floor; falling back to macro recall.")
        viable = available

    return max(viable, key=lambda n: viable[n].get("recall_macro", 0.0))


def dataset_fingerprint(path: Path) -> dict:
    if not path.exists():
        return {"path": path.name, "available": False}
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        digest.update(fh.read(1_000_000))
    stat = path.stat()
    return {
        "path":         path.name,
        "available":    True,
        "size_bytes":   stat.st_size,
        "modified_utc": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        "head_sha256":  digest.hexdigest(),
        "_note":        "head_sha256 covers the first 1 MB only.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", type=Path, default=DEFAULT_ARTIFACT_DIR)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    report = args.artifact_dir / "evaluation_report.txt"
    if not report.exists():
        raise SystemExit(f"{report} not found; cannot reconstruct a manifest.")

    print(f"[MANIFEST] Reading {report}")
    metrics = parse_evaluation_report(report)
    if not metrics:
        raise SystemExit("No per-model metrics parsed from the evaluation report.")
    print(f"[MANIFEST] Parsed {len(metrics)} model(s): {', '.join(sorted(metrics))}")

    served_name = select_served_model(metrics, args.artifact_dir)
    served_file = f"model_{served_name}.pkl"
    served = metrics[served_name]
    print(
        f"\n[MANIFEST] Served model: {served_name} "
        f"(macro recall {served.get('recall_macro')}, "
        f"worst class {served.get('worst_class')}={served.get('min_class_recall')})"
    )

    # Read the true class list and feature count from the artifacts themselves
    # rather than the report, so the manifest describes what will actually load.
    import joblib

    label_encoder = joblib.load(args.artifact_dir / "label_encoder.pkl")
    classes = [str(c) for c in label_encoder.classes_]
    feature_cols = json.loads(
        (args.artifact_dir / "feature_columns.json").read_text(encoding="utf-8")
    )

    import numpy
    import sklearn

    manifest = {
        "schema_version": 1,
        "generated_utc":  datetime.now(timezone.utc).isoformat(),
        "_generated_by":  "scripts/build_manifest.py (reconstructed, not a training run)",

        "served_model":      served_file,
        "served_model_name": served_name,
        "selection_rule": (
            f"highest macro recall among models with per-class recall "
            f">= {MIN_CLASS_RECALL:.0%}"
        ),

        "classes":       classes,
        "feature_count": len(feature_cols),
        "anomaly_layer": (args.artifact_dir / "iforest.pkl").exists()
                         and (args.artifact_dir / "autoencoder.pkl").exists(),

        "metrics": metrics,

        "reproducibility": {
            "dataset":      dataset_fingerprint(args.dataset),
            "config":       None,
            "random_state": 42,
            "python":       _plat_version(),
            "scikit_learn": sklearn.__version__,
            "numpy":        numpy.__version__,
            "joblib":       joblib.__version__,
            "_note": (
                "Reconstructed from artifacts/evaluation_report.txt; the "
                "original run's config was not recorded. Library versions are "
                "TODAY's, not necessarily the training run's -- a mismatch can "
                "fail to unpickle the estimator classes. Retrain to get an "
                "authoritative manifest."
            ),
        },
    }

    out = args.artifact_dir / "manifest.json"
    if args.dry_run:
        print("\n--- dry run, not written ---")
        print(json.dumps(manifest, indent=2)[:1500])
        return 0

    out.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"[MANIFEST] Wrote -> {out}")
    return 0


def _plat_version() -> str:
    return _platform.python_version()


if __name__ == "__main__":
    sys.exit(main())
