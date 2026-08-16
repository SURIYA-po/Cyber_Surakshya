"""
inference.py
============
NEW PIPELINE -- inference for the CICIDS2017 IDS.

Accepts:
  1. Python dict / list of dicts         (API, single/batch JSON)
  2. CICFlowMeter CSV                    (real CICFlowMeter output)
  3. Zeek conn.log                       (real Zeek output, TSV format)
  4. Generic feature CSV                 (pre-extracted features)

Dual-layer detection:
  Layer 1 -- Supervised Classifier        (RF / GB / DNN / VotingEnsemble)
  Layer 2 -- Anomaly Detection            (Isolation Forest + Autoencoder)

The anomaly layer acts as a "reactive second opinion":
  - If the supervised model says BENIGN but the anomaly layer fires,
    the final result is upgraded to INCONCLUSIVE (not just ignored).
  - If both layers flag attack -> confidence is boosted.

Usage
-----
  python inference.py --demo
  python inference.py --input flows.csv
  python inference.py --cicflow cicflowmeter_output.csv
  python inference.py --zeek conn.log
  python inference.py --input flows.csv --output predictions.csv
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import warnings
from dataclasses import dataclass
from io import StringIO
from typing import Any

import joblib
import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────────────────────────────────────
# ARTIFACT PATHS
# ─────────────────────────────────────────────────────────────────────────────

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
ARTIFACT_DIR = os.environ.get("ARTIFACT_DIR", os.path.join(BASE_DIR, "artifacts"))

SCALER_PATH     = os.path.join(ARTIFACT_DIR, "scaler.pkl")
LE_PATH         = os.path.join(ARTIFACT_DIR, "label_encoder.pkl")
FEAT_PATH       = os.path.join(ARTIFACT_DIR, "feature_columns.json")
IFOREST_PATH    = os.path.join(ARTIFACT_DIR, "iforest.pkl")
AE_PATH         = os.path.join(ARTIFACT_DIR, "autoencoder.pkl")
THRESHOLDS_PATH = os.path.join(ARTIFACT_DIR, "anomaly_thresholds.json")

# ─────────────────────────────────────────────────────────────────────────────
# AUTOENCODER PICKLE COMPATIBILITY
# ─────────────────────────────────────────────────────────────────────────────

def _register_autoencoder_for_unpickling() -> None:
    """Expose the trained autoencoder class under __main__ for legacy pickles."""
    try:
        from train import NumpyAutoencoder as _TrainAutoencoder
    except Exception:
        return

    main_module = sys.modules.get("__main__")
    if main_module is not None and not hasattr(main_module, "NumpyAutoencoder"):
        main_module.NumpyAutoencoder = _TrainAutoencoder


_register_autoencoder_for_unpickling()


# ─────────────────────────────────────────────────────────────────────────────
# CICFLOWMETER COLUMN NAME NORMALISATION
# CICFlowMeter output sometimes has leading spaces; strip and map to our names.
# ─────────────────────────────────────────────────────────────────────────────

# All column names from the cleaned CICIDS2017 dataset (52 features)
CICIDS_FEATURE_NAMES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Length of Fwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean",
    "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
    "PSH Flag Count", "ACK Flag Count", "Average Packet Size", "Subflow Fwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd",
    "min_seg_size_forward", "Active Mean", "Active Max", "Active Min",
    "Idle Mean", "Idle Max", "Idle Min",
]

# CICFlowMeter uses slightly different names in some versions -- normalise them
CICFLOW_ALIASES: dict[str, str] = {
    # Aliases with leading space (old CICFlowMeter versions)
    " Destination Port":             "Destination Port",
    " Flow Duration":                "Flow Duration",
    " Total Fwd Packets":            "Total Fwd Packets",
    "Total Length of Fwd Packets":   "Total Length of Fwd Packets",
    " Total Length of Bwd Packets":  "Total Length of Bwd Packets",
    " Fwd Packet Length Max":        "Fwd Packet Length Max",
    " Fwd Packet Length Min":        "Fwd Packet Length Min",
    " Fwd Packet Length Mean":       "Fwd Packet Length Mean",
    "Bwd Packet Length Max":         "Bwd Packet Length Max",
    " Bwd Packet Length Mean":       "Bwd Packet Length Mean",
    "Flow Bytes/s":                  "Flow Bytes/s",
    " Flow Packets/s":               "Flow Packets/s",
    "Fwd Packets/s":                 "Fwd Packets/s",
    " Bwd Packets/s":                "Bwd Packets/s",
    " Flow IAT Mean":                "Flow IAT Mean",
    " Flow IAT Std":                 "Flow IAT Std",
    " Flow IAT Max":                 "Flow IAT Max",
    " Flow IAT Min":                 "Flow IAT Min",
    "Fwd IAT Total":                 "Fwd IAT Total",
    " Fwd IAT Mean":                 "Fwd IAT Mean",
    " Fwd IAT Std":                  "Fwd IAT Std",
    "Bwd IAT Total":                 "Bwd IAT Total",
    " Bwd IAT Mean":                 "Bwd IAT Mean",
    " Bwd IAT Std":                  "Bwd IAT Std",
    "FIN Flag Count":                "FIN Flag Count",
    " SYN Flag Count":               "SYN Flag Count",
    " RST Flag Count":               "RST Flag Count",
    " PSH Flag Count":               "PSH Flag Count",
    " ACK Flag Count":               "ACK Flag Count",
    " URG Flag Count":               "URG Flag Count",
    " Fwd Header Length":            "Fwd Header Length",
    " Bwd Header Length":            "Bwd Header Length",
    "Subflow Fwd Packets":           "Subflow Fwd Packets",
    " Subflow Fwd Bytes":            "Subflow Fwd Bytes",
    " Subflow Bwd Packets":          "Subflow Bwd Packets",
    " Subflow Bwd Bytes":            "Subflow Bwd Bytes",
    "Init_Win_bytes_forward":        "Init_Win_bytes_forward",
    " Init_Win_bytes_backward":      "Init_Win_bytes_backward",
    " act_data_pkt_fwd":             "act_data_pkt_fwd",
    " min_seg_size_forward":         "min_seg_size_forward",
    "Active Mean":                   "Active Mean",
    " Active Std":                   "Active Std",
    "Idle Mean":                     "Idle Mean",
    " Idle Std":                     "Idle Std",
    # CICFlowMeter v2 names
    "SYN Flag Cnt":                  "SYN Flag Count",
    "FIN Flag Cnt":                  "FIN Flag Count",
    "RST Flag Cnt":                  "RST Flag Count",
    "PSH Flag Cnt":                  "PSH Flag Count",
    "ACK Flag Cnt":                  "ACK Flag Count",
    "URG Flag Cnt":                  "URG Flag Count",
    "Tot Fwd Pkts":                  "Total Fwd Packets",
    "Tot Bwd Pkts":                  "Total Backward Packets",
    "TotLen Fwd Pkts":               "Total Length of Fwd Packets",
    "TotLen Bwd Pkts":               "Total Length of Bwd Packets",
    "Fwd Pkt Len Max":               "Fwd Packet Length Max",
    "Fwd Pkt Len Min":               "Fwd Packet Length Min",
    "Fwd Pkt Len Mean":              "Fwd Packet Length Mean",
    "Fwd Pkt Len Std":               "Fwd Packet Length Std",
    "Bwd Pkt Len Max":               "Bwd Packet Length Max",
    "Bwd Pkt Len Min":               "Bwd Packet Length Min",
    "Bwd Pkt Len Mean":              "Bwd Packet Length Mean",
    "Bwd Pkt Len Std":               "Bwd Packet Length Std",
    "Pkt Len Min":                   "Min Packet Length",
    "Pkt Len Max":                   "Max Packet Length",
    "Pkt Len Mean":                  "Packet Length Mean",
    "Pkt Len Std":                   "Packet Length Std",
    "Pkt Len Var":                   "Packet Length Variance",
    "Pkt Size Avg":                  "Average Packet Size",
    "Fwd Seg Size Avg":              "Avg Fwd Segment Size",
    "Bwd Seg Size Avg":              "Avg Bwd Segment Size",
    "Fwd Byts/b Avg":                "Fwd Avg Bytes/Bulk",
    "Bwd Byts/b Avg":                "Bwd Avg Bytes/Bulk",
    "Subflow Fwd Pkts":              "Subflow Fwd Packets",
    "Subflow Bwd Pkts":              "Subflow Bwd Packets",
    "Subflow Bwd Byts":              "Subflow Bwd Bytes",
    "Init Fwd Win Byts":             "Init_Win_bytes_forward",
    "Init Bwd Win Byts":             "Init_Win_bytes_backward",
    "Fwd Act Data Pkts":             "act_data_pkt_fwd",
    "Fwd Seg Size Min":              "min_seg_size_forward",
    "Active Std":                    "Active Std",
    "Idle Std":                      "Idle Std",
    "Label":                         "__LABEL__",     # drop
    " Label":                        "__LABEL__",
    "Attack Type":                   "__LABEL__",
}


# ─────────────────────────────────────────────────────────────────────────────
# 1. LOAD ARTIFACTS
# ─────────────────────────────────────────────────────────────────────────────

MANIFEST_NAME = "manifest.json"


def load_manifest(artifact_dir: str = ARTIFACT_DIR) -> dict | None:
    """Read artifacts/manifest.json, or None when it is absent/unreadable.

    Written by train.py. Records which model is served and what produced it.
    """
    path = os.path.join(artifact_dir, MANIFEST_NAME)
    try:
        with open(path, encoding="utf-8") as fh:
            manifest = json.load(fh)
    except FileNotFoundError:
        return None
    except Exception as exc:
        print(f"  [WARN] {path} is unreadable ({exc}); falling back to name order.")
        return None
    return manifest if isinstance(manifest, dict) else None


def resolve_model_path(artifact_dir: str, requested_model: str | None = None) -> str:
    """Resolve which model artifact to serve.

    Precedence:
      1. An explicitly requested filename.
      2. ``manifest.json``'s ``served_model`` -- an auditable, deliberate choice
         recorded by training.
      3. A hardcoded preference list (legacy fallback).

    Step 2 exists because step 3 decides the served model by LIST ORDER and
    whatever files happen to be present. Three of the four models this project
    trains have 0.08-0.10 recall on WEBATTACK while scoring >0.99 weighted F1,
    so "whichever file is found first" is a genuinely dangerous rule: dropping
    a `model.pkl` built from the wrong estimator silently blinds the detector
    to an entire attack family, with every headline metric still reading 99%.
    """
    if requested_model:
        candidate = os.path.join(artifact_dir, requested_model)
        if os.path.exists(candidate):
            return candidate

    manifest = load_manifest(artifact_dir)
    if manifest:
        served = manifest.get("served_model")
        if served:
            candidate = os.path.join(artifact_dir, str(served))
            if os.path.exists(candidate):
                return candidate
            print(
                f"  [WARN] {MANIFEST_NAME} names {served!r} as the served model "
                f"but it is not in {artifact_dir}. Falling back to name order."
            )

    preferred_names = [
        "model.pkl",
        "model_DNN.pkl",
        "model_GradientBoosting.pkl",
        "model_RandomForest.pkl",
        "model_VotingEnsemble.pkl",
    ]

    for name in preferred_names:
        candidate = os.path.join(artifact_dir, name)
        if os.path.exists(candidate):
            return candidate

    return os.path.join(artifact_dir, requested_model or "model.pkl")


MODEL_PATH = resolve_model_path(ARTIFACT_DIR)


class ArtifactError(RuntimeError):
    """Raised when the artifacts required for inference cannot be loaded.

    This is deliberately fatal. The previous behaviour substituted a stub
    model that returned ``BENIGN`` at confidence 1.0 for every flow, which
    turned a missing file into an IDS that reported the network clean --
    indistinguishable, from the outside, from a working one. A detector that
    cannot load its model must refuse to answer, not answer "safe".
    """


class IDSArtifacts:
    """Container for all inference-time artifacts.

    Raises:
        ArtifactError: any of the four required artifacts (model, scaler,
            label encoder, feature list) is missing or unreadable. The
            anomaly layer remains optional -- it degrades to supervised-only
            with ``anomaly_ready = False``, which callers can inspect.
    """

    def __init__(
        self,
        model_path:      str = MODEL_PATH,
        scaler_path:     str = SCALER_PATH,
        le_path:         str = LE_PATH,
        feat_path:       str = FEAT_PATH,
        iforest_path:    str = IFOREST_PATH,
        ae_path:         str = AE_PATH,
        thresholds_path: str = THRESHOLDS_PATH,
    ):
        print("[INFERENCE] Loading artifacts...")

        # Every required artifact is checked before any is loaded, so the
        # error names all of them at once instead of one per re-run.
        missing = [
            label
            for label, path in (
                ("model",         model_path),
                ("scaler",        scaler_path),
                ("label encoder", le_path),
                ("feature list",  feat_path),
            )
            if not os.path.exists(path)
        ]
        if missing:
            raise ArtifactError(
                f"Cannot load IDS artifacts -- missing: {', '.join(missing)}. "
                f"Looked in {os.path.dirname(model_path) or '.'}. "
                "Train the model (`python train.py`) or point ARTIFACT_DIR at "
                "a directory containing model.pkl, scaler.pkl, "
                "label_encoder.pkl and feature_columns.json. Detection is "
                "disabled until this is resolved."
            )

        try:
            self.model  = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            self.le     = joblib.load(le_path)
            with open(feat_path) as fh:
                self.feature_cols: list[str] = json.load(fh)
        except Exception as exc:
            raise ArtifactError(
                f"IDS artifacts exist but could not be loaded: {exc}"
            ) from exc

        if not self.feature_cols:
            raise ArtifactError(f"{feat_path} contains an empty feature list.")

        # A scaler fitted on a different number of features than the feature
        # list declares means the two artifacts came from different training
        # runs. Scaling would still "work" -- silently, on misaligned columns.
        expected = getattr(self.scaler, "n_features_in_", None)
        if expected is not None and expected != len(self.feature_cols):
            raise ArtifactError(
                f"Artifact mismatch: scaler expects {expected} features but "
                f"{feat_path} lists {len(self.feature_cols)}. These artifacts "
                "are from different training runs; retrain to regenerate a "
                "consistent set."
            )

        # Anomaly layer (optional -- may not exist if --no_anomaly was used)
        self.iforest     = None
        self.autoencoder = None
        self.if_threshold  = None
        self.ae_threshold  = None
        self.anomaly_ready = False

        if os.path.exists(iforest_path) and os.path.exists(ae_path):
            try:
                self.iforest     = joblib.load(iforest_path)
                self.autoencoder = joblib.load(ae_path)
                if os.path.exists(thresholds_path):
                    with open(thresholds_path) as fh:
                        thresholds = json.load(fh)
                    self.if_threshold = thresholds["if_threshold"]
                    self.ae_threshold = thresholds["ae_threshold"]
                self.anomaly_ready = True
                # ASCII only. A Unicode tick here raised UnicodeEncodeError on
                # a Windows cp1252 console, which the except below swallowed --
                # printing "Could not load anomaly artifacts" for a layer that
                # had in fact loaded correctly.
                print("  Anomaly layer: OK (IsolationForest + Autoencoder)")
            except Exception as e:
                print(f"  [WARN] Could not load anomaly artifacts: {e}")
        else:
            print("  Anomaly layer: MISSING (artifacts not found - run without --no_anomaly)")

        print(f"  Model      : {type(self.model).__name__}")
        print(f"  Features   : {len(self.feature_cols)}")
        print(f"  Classes    : {list(self.le.classes_)}")

    @property
    def label_encoder(self):
        return self.le

    @property
    def feature_columns(self):
        return self.feature_cols


def load_anomaly_layer(
    iforest_path:    str = IFOREST_PATH,
    ae_path:         str = AE_PATH,
    thresholds_path: str = THRESHOLDS_PATH,
) -> tuple:
    """Load the optional anomaly layer.

    Returns ``(iforest, autoencoder, if_threshold, ae_threshold)``, all None
    when the layer is unavailable. Unlike the supervised artifacts this is
    genuinely optional -- supervised-only detection is degraded but still
    correct, so a missing anomaly layer warns rather than raises.
    """
    if not (os.path.exists(iforest_path) and os.path.exists(ae_path)):
        return (None, None, None, None)
    try:
        iforest     = joblib.load(iforest_path)
        autoencoder = joblib.load(ae_path)
        if_threshold = ae_threshold = None
        if os.path.exists(thresholds_path):
            with open(thresholds_path) as fh:
                thresholds = json.load(fh)
            if_threshold = thresholds.get("if_threshold")
            ae_threshold = thresholds.get("ae_threshold")
        if if_threshold is None or ae_threshold is None:
            print(
                f"  [WARN] {thresholds_path} is missing if_threshold/"
                "ae_threshold; anomaly layer disabled."
            )
            return (None, None, None, None)
        return (iforest, autoencoder, if_threshold, ae_threshold)
    except Exception as exc:
        print(f"  [WARN] Could not load anomaly artifacts: {exc}")
        return (None, None, None, None)


def load_artifacts(
    model_path:      str = MODEL_PATH,
    scaler_path:     str = SCALER_PATH,
    le_path:         str = LE_PATH,
    feat_path:       str = FEAT_PATH,
    iforest_path:    str = IFOREST_PATH,
    ae_path:         str = AE_PATH,
    thresholds_path: str = THRESHOLDS_PATH,
) -> tuple:
    """Load core artifacts and return (model, scaler, le, feature_cols)."""
    arts = IDSArtifacts(
        model_path=model_path,
        scaler_path=scaler_path,
        le_path=le_path,
        feat_path=feat_path,
        iforest_path=iforest_path,
        ae_path=ae_path,
        thresholds_path=thresholds_path,
    )
    return arts.model, arts.scaler, arts.le, arts.feature_cols


# ─────────────────────────────────────────────────────────────────────────────
# 2. PREPROCESSING FOR INFERENCE
# ─────────────────────────────────────────────────────────────────────────────

def _python_cicflowmeter_contract():
    """Return (source->model rename map, features needing seconds->µs), or None.

    The Python ``cicflowmeter`` package emits snake_case columns in SECONDS;
    CICIDS2017 uses Title Case in MICROSECONDS. ``CICFLOW_ALIASES`` below only
    ever covered the *Java* CICFlowMeter spellings, so a Python-cicflowmeter
    CSV matched zero of the 42 model features and every one was zero-filled --
    producing BENIGN at confidence 1.0 for an entire capture.

    The mapping is imported from ``ingestion.flows.normalizer`` rather than
    restated here. Two copies of a units table is precisely how the original
    bug survived: one copy gets fixed and the other does not.
    """
    try:
        from ingestion.flows.normalizer import (
            FEATURE_SOURCE_MAP,
            MICROSECOND_FEATURES,
        )
    except Exception:  # ingestion layer not installed -- Java path still works
        return None
    return (
        {source: model for model, source in FEATURE_SOURCE_MAP.items()},
        MICROSECOND_FEATURES,
    )


def _looks_like_python_cicflowmeter(columns) -> bool:
    """Detect Python-cicflowmeter output by its distinctive snake_case names."""
    present = {str(c).strip() for c in columns}
    # These three appear together only in the Python implementation's schema.
    return {"flow_duration", "tot_fwd_pkts", "fwd_pkt_len_max"} <= present


def _normalize_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """
    Strip whitespace, apply CICFlowMeter alias map, drop label columns.
    Returns a clean DataFrame with standardised column names.

    Handles three input dialects:
      * CICIDS2017 / Java CICFlowMeter Title Case  (via CICFLOW_ALIASES)
      * Python cicflowmeter snake_case in seconds  (renamed AND rescaled)
      * already-normalised frames                  (pass through)
    """
    df = df.copy()
    # Strip whitespace from column names first
    df.columns = df.columns.str.strip()

    # ── Python cicflowmeter: rename, then convert seconds -> microseconds ──
    contract = _python_cicflowmeter_contract()
    if contract is not None and _looks_like_python_cicflowmeter(df.columns):
        source_to_model, microsecond_features = contract
        df = df.rename(columns={
            source: model
            for source, model in source_to_model.items()
            if source in df.columns
        })
        for feature in microsecond_features:
            if feature in df.columns:
                df[feature] = (
                    pd.to_numeric(df[feature], errors="coerce").fillna(0.0)
                    * 1_000_000.0
                )
        print(
            f"[INFERENCE] Detected Python cicflowmeter output: renamed "
            f"{len(source_to_model)} columns, converted "
            f"{len(microsecond_features)} time features seconds -> microseconds."
        )

    # Apply alias mapping
    rename_map = {}
    for col in df.columns:
        alias = CICFLOW_ALIASES.get(col)
        if alias == "__LABEL__":
            df = df.drop(columns=[col], errors="ignore")
            continue
        if alias:
            rename_map[col] = alias

    df = df.rename(columns=rename_map)

    # Drop any remaining label-like columns
    for lbl_col in ["Label", "Attack Type", "label", "Class"]:
        if lbl_col in df.columns:
            df = df.drop(columns=[lbl_col])

    return df


class FeatureCoverageError(ValueError):
    """Raised when too few model features are present in the input.

    Zero-filling a missing feature does not fail -- it produces a *confident
    wrong* prediction, which nothing downstream can detect. This error makes
    the failure visible at the boundary where it happens.
    """


# Below this fraction of matched features, a prediction is not meaningful.
# The observed failure mode was 0.0 (no column names matched at all), so any
# non-trivial floor catches it; 0.5 also catches half-mapped schemas.
DEFAULT_MIN_FEATURE_COVERAGE = 0.5


def preprocess_for_inference(
    df_raw: pd.DataFrame,
    feature_cols: list[str],
    scaler,
    *,
    min_coverage: float = 0.0,
    context: str = "input",
) -> np.ndarray:
    """
    Align raw flow data to the model's feature schema, then scale.

    Steps
    -----
    1. Normalise column names (strip spaces + apply CICFlowMeter aliases)
    2. Build aligned DataFrame with model's expected feature columns
       (missing columns -> zero-filled)
    3. Coerce to numeric, replace inf/NaN -> 0
    4. Apply trained StandardScaler

    This function works for all input types:
    - CICFlowMeter CSV output
    - Zeek conn.log (after translate_zeek_conn_log)
    - Raw dicts / JSON
    """
    df = _normalize_column_names(df_raw)

    # Build aligned frame (zero-fill missing)
    aligned = pd.DataFrame(
        0.0,
        index=df.index,
        columns=feature_cols,
    )

    matched: list[str] = []
    for col in feature_cols:
        col_s = col.strip()
        if col_s in df.columns:
            aligned[col] = pd.to_numeric(df[col_s], errors="coerce").fillna(0.0)
            matched.append(col)

    # ── Coverage check ───────────────────────────────────────────────────────
    # Everything not matched above is still sitting at its 0.0 initial value.
    coverage = len(matched) / len(feature_cols) if feature_cols else 0.0
    if coverage < 1.0:
        missing = [c for c in feature_cols if c not in matched]
        message = (
            f"[INFERENCE] {context}: only {len(matched)}/{len(feature_cols)} "
            f"model features matched ({coverage:.0%}); the remaining "
            f"{len(missing)} were zero-filled. First missing: {missing[:5]}"
        )
        if coverage < min_coverage:
            raise FeatureCoverageError(
                f"{message}. Refusing to predict -- a mostly zero-filled "
                "feature vector yields a confident, meaningless label. Check "
                "that the input column names match "
                "artifacts/feature_columns.json."
            )
        print(message)

    # Replace inf
    aligned = aligned.replace([float("inf"), float("-inf")], 0.0)

    # Scale
    X = scaler.transform(aligned.values.astype(np.float32))
    return X


# ─────────────────────────────────────────────────────────────────────────────
# 3. PREDICTION (DUAL-LAYER)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class _ResolvedArtifacts:
    """The pieces `_run_prediction` needs, however the caller supplied them."""

    model:         Any
    scaler:        Any
    label_encoder: Any
    feature_cols:  Any
    iforest:       Any = None
    autoencoder:   Any = None
    if_threshold:  float | None = None
    ae_threshold:  float | None = None

    @property
    def anomaly_ready(self) -> bool:
        return (
            self.iforest is not None
            and self.autoencoder is not None
            # Thresholds are required: `scores < None` raises TypeError, and
            # treating a missing threshold as 0 would flag either everything
            # or nothing.
            and self.if_threshold is not None
            and self.ae_threshold is not None
        )


def predict_supervised(
    df_raw:       pd.DataFrame,
    model:        Any,
    scaler:       Any,
    label_encoder: Any,
    feature_cols: Any,
    *,
    return_proba: bool = True,
    min_coverage: float = 0.0,
    context:      str = "input",
) -> pd.DataFrame:
    """Layer 1 only: classify with the supervised model.

    Use this when you genuinely have nothing but the four core artifacts.
    Anything that has an artifacts container should call `predict_dual_layer`
    instead -- supervised-only means a novel attack is confidently sorted into
    the nearest known class with no second opinion.
    """
    return _run_prediction(
        df_raw,
        _ResolvedArtifacts(model, scaler, label_encoder, feature_cols),
        return_proba=return_proba,
        min_coverage=min_coverage,
        context=context,
    )


def predict_dual_layer(
    df_raw:    pd.DataFrame,
    artifacts: Any,
    *,
    return_proba: bool = True,
    min_coverage: float = 0.0,
    context:      str = "input",
) -> pd.DataFrame:
    """Both layers: supervised classifier plus unsupervised anomaly detection.

    `artifacts` is any object exposing `model`, `scaler`, `le`/`label_encoder`
    and `feature_cols`/`feature_columns` -- both `inference.IDSArtifacts` and
    `adapters.detection.ids_adapter.IDSArtifacts` qualify. The anomaly layer
    runs when `iforest`, `autoencoder` and both thresholds are present, and is
    skipped (supervised-only) otherwise.
    """
    return _run_prediction(
        df_raw,
        _resolve_artifacts(artifacts),
        return_proba=return_proba,
        min_coverage=min_coverage,
        context=context,
    )


def _resolve_artifacts(artifacts: Any) -> _ResolvedArtifacts:
    """Read the standard attribute names off an artifacts container."""
    return _ResolvedArtifacts(
        model=getattr(artifacts, "model", None),
        scaler=getattr(artifacts, "scaler", None),
        label_encoder=getattr(
            artifacts, "le", getattr(artifacts, "label_encoder", None)
        ),
        feature_cols=getattr(
            artifacts, "feature_cols", getattr(artifacts, "feature_columns", None)
        ),
        iforest=getattr(artifacts, "iforest", None),
        autoencoder=getattr(artifacts, "autoencoder", None),
        if_threshold=getattr(artifacts, "if_threshold", None),
        ae_threshold=getattr(artifacts, "ae_threshold", None),
    )


def predict(
    df_raw:      pd.DataFrame,
    artifacts:   Any,
    scaler:      Any = None,
    le:          Any = None,
    feature_cols: Any = None,
    return_proba: bool = True,
    *,
    min_coverage: float = 0.0,
    context: str = "input",
) -> pd.DataFrame:
    """Backwards-compatible front door. Prefer the two explicit functions.

    This signature accepted either `predict(df, artifacts_container)` or
    `predict(df, model, scaler, le, feature_cols)` and told them apart with
    `isinstance(scaler, bool)` checks. The ambiguity was not cosmetic: the
    unpacked form silently hard-coded `anomaly_ready = False`, so the adapter
    that called it disabled the anomaly layer for every detection the platform
    made, and nothing in the call site suggested that.

    New code should call `predict_supervised` or `predict_dual_layer`, whose
    names state which layers run.
    """
    positional_form = (
        scaler is not None
        and not isinstance(scaler, bool)
        and le is not None
        and feature_cols is not None
    )
    if positional_form:
        return predict_supervised(
            df_raw, artifacts, scaler, le, feature_cols,
            return_proba=return_proba,
            min_coverage=min_coverage,
            context=context,
        )

    # Legacy quirk: `predict(df, artifacts, False)` passed return_proba third.
    actual_proba = scaler if isinstance(scaler, bool) else return_proba
    return predict_dual_layer(
        df_raw, artifacts,
        return_proba=actual_proba,
        min_coverage=min_coverage,
        context=context,
    )


def _run_prediction(
    df_raw:    pd.DataFrame,
    resolved:  _ResolvedArtifacts,
    *,
    return_proba: bool,
    min_coverage: float,
    context:      str,
) -> pd.DataFrame:
    """Shared body: preprocess, classify, optionally score anomalies."""
    X = preprocess_for_inference(
        df_raw, resolved.feature_cols, resolved.scaler,
        min_coverage=min_coverage,
        context=context,
    )

    # ── Layer 1: Supervised ──────────────────────────────────────────────────
    y_pred_enc = resolved.model.predict(X)
    y_pred     = resolved.label_encoder.inverse_transform(y_pred_enc)

    results = pd.DataFrame({"prediction": y_pred}, index=df_raw.index)

    if return_proba and hasattr(resolved.model, "predict_proba"):
        proba = resolved.model.predict_proba(X)
        results["confidence"] = proba.max(axis=1).round(4)
        for i, cls in enumerate(resolved.label_encoder.classes_):
            results[f"prob_{cls}"] = proba[:, i].round(4)
    else:
        results["confidence"] = 1.0

    # ── Layer 2: Anomaly ─────────────────────────────────────────────────────
    if_anomaly = np.zeros(len(X), dtype=bool)
    ae_anomaly = np.zeros(len(X), dtype=bool)

    if resolved.anomaly_ready:
        if_scores  = resolved.iforest.score_samples(X)
        if_anomaly = if_scores < resolved.if_threshold

        ae_errors  = resolved.autoencoder.reconstruction_error(X)
        ae_anomaly = ae_errors > resolved.ae_threshold

    results["if_anomaly"] = if_anomaly
    results["ae_anomaly"] = ae_anomaly
    results["is_anomaly"] = if_anomaly | ae_anomaly

    # ── Final status ─────────────────────────────────────────────────────────
    CONFIDENCE_THRESHOLD = 0.50

    def _final_status(row):
        pred  = row["prediction"]
        conf  = row["confidence"]
        anom  = row["is_anomaly"]

        if pred == "BENIGN":
            if anom:
                return "INCONCLUSIVE"   # model says safe but anomaly fired
            return "BENIGN"
        else:
            if conf >= CONFIDENCE_THRESHOLD:
                return "DETECTED"
            return "INCONCLUSIVE"       # attack predicted but low confidence

    results["final_status"] = results.apply(_final_status, axis=1)

    return results


# ─────────────────────────────────────────────────────────────────────────────
# 4. CICFLOWMETER CSV INGESTION
# ─────────────────────────────────────────────────────────────────────────────

def load_cicflowmeter_csv(path: str) -> pd.DataFrame:
    """
    Load a CICFlowMeter CSV output file.

    CICFlowMeter writes a header row then data rows.  It may also include
    a 'Label' column (ground-truth from the tool); that is dropped.

    Compatible with:
      - CICFlowMeter v3 (2018 release, with leading spaces in header)
      - CICFlowMeter v4 (2021+, clean header)
      - CICIDS2017 raw CSVs
    """
    print(f"[CICFlow] Loading: {path}")
    df = pd.read_csv(path, low_memory=False, encoding="utf-8",
                     encoding_errors="replace")
    df = _normalize_column_names(df)
    print(f"  Rows: {len(df):,}  |  Columns: {len(df.columns)}")
    return df


# ─────────────────────────────────────────────────────────────────────────────
# 5. ZEEK conn.log INGESTION & TRANSLATION
# ─────────────────────────────────────────────────────────────────────────────

def load_zeek_conn_log(path: str) -> pd.DataFrame:
    """
    Parse a Zeek conn.log (TSV, comment lines starting with #).

    Handles both:
      - Standard Zeek text conn.log (with #fields header)
      - JSON-format conn.log  (if Zeek is configured for JSON output)
    """
    print(f"[ZEEK] Loading conn.log: {path}")

    # Detect JSON format
    with open(path, encoding="utf-8", errors="replace") as fh:
        first_line = fh.readline().strip()

    if first_line.startswith("{"):
        # JSON-lines format
        rows = []
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        df_zeek = pd.DataFrame(rows)
    else:
        # TSV text format
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()

        header_line = None
        data_lines  = []
        for line in lines:
            if line.startswith("#fields\t"):
                header_line = line.strip().replace("#fields\t", "").split("\t")
            elif not line.startswith("#"):
                data_lines.append(line)

        if not data_lines:
            raise ValueError(f"No data rows found in Zeek log: {path}")

        if header_line:
            data_str = "".join(data_lines)
            df_zeek = pd.read_csv(
                StringIO(data_str), sep="\t",
                names=header_line,
                na_values=["-", "(empty)", ""],
                low_memory=False,
            )
        else:
            df_zeek = pd.read_csv(
                path, sep="\t", comment="#",
                na_values=["-", "(empty)", ""],
                low_memory=False,
            )

    print(f"  Zeek records: {len(df_zeek):,}")
    return df_zeek


def translate_zeek_conn_log(df_zeek: pd.DataFrame) -> pd.DataFrame:
    """
    Map Zeek conn.log fields to CICIDS2017-compatible feature names.

    Zeek conn.log coverage:
      ~15 of 52 CICIDS2017 features can be directly mapped or derived.
      Remaining features are zero-filled.  The model degrades gracefully --
      tree-based models and the anomaly layer use whatever is available.

    Field mapping:
      id.resp_p  -> Destination Port
      duration   -> Flow Duration (seconds × 1e6 -> microseconds)
      orig_pkts  -> Total Fwd Packets
      resp_pkts  -> (Total Backward Packets -- derived)
      orig_bytes -> Total Length of Fwd Packets
      resp_bytes -> (Total Length of Bwd Packets -- derived)
      history    -> FIN/PSH/ACK flag counts (parsed)
      duration + bytes -> Flow Bytes/s, Flow Packets/s (derived)
    """
    df = df_zeek.copy()
    out = pd.DataFrame(index=df.index)

    def _get(col, default=0):
        return pd.to_numeric(df.get(col, default), errors="coerce").fillna(0)

    # ── Direct mappings ──────────────────────────────────────────────────────
    out["Destination Port"]            = _get("id.resp_p")
    out["Flow Duration"]               = _get("duration") * 1_000_000  # s -> µs
    out["Total Fwd Packets"]           = _get("orig_pkts")
    out["Total Length of Fwd Packets"] = _get("orig_bytes")

    # Approx backward as resp_ fields
    resp_pkts  = _get("resp_pkts")
    resp_bytes = _get("resp_bytes")

    # ── Derived metrics ──────────────────────────────────────────────────────
    dur_s       = _get("duration").replace(0, np.nan)
    orig_bytes  = _get("orig_bytes")
    total_pkts  = _get("orig_pkts") + resp_pkts
    total_bytes = orig_bytes + resp_bytes

    out["Flow Bytes/s"]    = (total_bytes / dur_s).fillna(0).clip(0)
    out["Flow Packets/s"]  = (total_pkts  / dur_s).fillna(0).clip(0)
    out["Fwd Packets/s"]   = (_get("orig_pkts") / dur_s).fillna(0).clip(0)
    out["Bwd Packets/s"]   = (resp_pkts  / dur_s).fillna(0).clip(0)

    out["Average Packet Size"] = (
        total_bytes / total_pkts.replace(0, np.nan)
    ).fillna(0)
    out["Subflow Fwd Bytes"]  = orig_bytes
    out["Fwd Header Length"]  = _get("orig_ip_bytes")
    out["Bwd Header Length"]  = _get("resp_ip_bytes")

    # ── TCP flags from Zeek history ──────────────────────────────────────────
    # Zeek history field characters:
    #   S/s = SYN (uppercase = originator, lowercase = responder)
    #   F/f = FIN, R/r = RST, P/p = PSH, A/a = ACK, U/u = URG
    if "history" in df.columns:
        hist = df["history"].fillna("").astype(str)
        out["SYN Flag Count"] = (hist.str.count("S") + hist.str.count("s")).astype(int)
        out["FIN Flag Count"] = (hist.str.count("F") + hist.str.count("f")).astype(int)
        out["RST Flag Count"] = (hist.str.count("R") + hist.str.count("r")).astype(int)
        out["PSH Flag Count"] = (hist.str.count("P") + hist.str.count("p")).astype(int)
        out["ACK Flag Count"] = (hist.str.count("A") + hist.str.count("a")).astype(int)
        out["URG Flag Count"] = (hist.str.count("U") + hist.str.count("u")).astype(int)
    else:
        for flag in ["SYN Flag Count", "FIN Flag Count", "RST Flag Count",
                     "PSH Flag Count", "ACK Flag Count", "URG Flag Count"]:
            out[flag] = 0

    # Init window sizes (not in basic conn.log -> 0)
    out["Init_Win_bytes_forward"]  = 0.0
    out["Init_Win_bytes_backward"] = 0.0

    # Fwd IAT / Bwd IAT (not in conn.log -> 0)
    for col in [
        "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
        "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
        "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
        "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
        "Fwd Packet Length Std", "Bwd Packet Length Max", "Bwd Packet Length Min",
        "Bwd Packet Length Mean", "Bwd Packet Length Std",
        "Min Packet Length", "Max Packet Length", "Packet Length Mean",
        "Packet Length Std", "Packet Length Variance",
        "Active Mean", "Active Max", "Active Min",
        "Idle Mean",   "Idle Max",   "Idle Min",
        "act_data_pkt_fwd", "min_seg_size_forward",
    ]:
        out[col] = 0.0

    print(f"  Translated to {len(out.columns)} CICIDS2017-compatible features.")
    return out


# ─────────────────────────────────────────────────────────────────────────────
# 6. BATCH CSV PREDICTION
# ─────────────────────────────────────────────────────────────────────────────

def predict_csv(
    input_path:  str,
    output_path: str,
    artifacts:   IDSArtifacts,
    input_type:  str = "auto",      # 'auto' | 'cicflow' | 'generic'
) -> pd.DataFrame:
    """
    Load a CSV, predict, save results.

    input_type='auto'    -> try CICFlowMeter normalisation, fallback to generic
    input_type='cicflow' -> explicitly treat as CICFlowMeter output
    input_type='generic' -> treat as pre-extracted CICIDS2017-format features
    """
    print(f"\n[BATCH] Loading CSV: {input_path}")
    df = load_cicflowmeter_csv(input_path)

    results = predict(df, artifacts)
    out_df  = pd.concat([df.reset_index(drop=True),
                          results.reset_index(drop=True)], axis=1)
    out_df.to_csv(output_path, index=False)

    print(f"[BATCH] Predictions saved -> {output_path}")
    print("\n[BATCH] Prediction summary:")
    print(results["final_status"].value_counts().to_string())
    print("\n[BATCH] Attack type distribution:")
    print(results["prediction"].value_counts().to_string())

    return results


# ─────────────────────────────────────────────────────────────────────────────
# 7. ZEEK PREDICTION
# ─────────────────────────────────────────────────────────────────────────────

def predict_zeek_log(
    zeek_path:   str,
    output_path: str | None = None,
    artifacts:   Any = None,
    *args,
    **kwargs,
) -> pd.DataFrame:
    """Parse Zeek conn.log, translate, predict."""
    if artifacts is None and len(args) >= 4:
        model, scaler, le, feat_cols = args[:4]
        class TempArtifacts:
            pass
        artifacts = TempArtifacts()
        artifacts.model = model
        artifacts.scaler = scaler
        artifacts.le = le
        artifacts.feature_cols = feat_cols
        artifacts.anomaly_ready = False

    df_zeek       = load_zeek_conn_log(zeek_path)
    df_translated = translate_zeek_conn_log(df_zeek)
    results       = predict(df_translated, artifacts)

    if output_path:
        out_df = pd.concat([df_zeek.reset_index(drop=True),
                             results.reset_index(drop=True)], axis=1)
        out_df.to_csv(output_path, index=False)
        print(f"[ZEEK] Predictions saved -> {output_path}")

    print("\n[ZEEK] Final status distribution:")
    print(results["final_status"].value_counts().to_string())
    print("\n[ZEEK] Predicted attack types:")
    print(results["prediction"].value_counts().to_string())

    return results


# ─────────────────────────────────────────────────────────────────────────────
# 8. SINGLE RECORD PREDICTION  (used by IDSDetectionAdapter / FastAPI)
# ─────────────────────────────────────────────────────────────────────────────

def predict_single(
    flow_data:  dict | list,
    artifacts:  IDSArtifacts,
) -> dict:
    """
    Predict a single flow record (dict) or batch (list of dicts).

    Returns
    -------
    For a single dict:
        {
          "prediction":   "DDOS",
          "confidence":   0.97,
          "final_status": "DETECTED",
          "is_anomaly":   False,
          "if_anomaly":   False,
          "ae_anomaly":   False,
          "probabilities": {"BENIGN": 0.01, "DDOS": 0.97, ...}
        }
    For a list: returns a list of the above.
    """
    if isinstance(flow_data, dict):
        df_raw   = pd.DataFrame([flow_data])
        results  = predict(df_raw, artifacts)
        row      = results.iloc[0]
        prob_cols = {k.replace("prob_", ""): float(v)
                     for k, v in row.items() if k.startswith("prob_")}
        return {
            "prediction":   row["prediction"],
            "confidence":   float(row["confidence"]),
            "final_status": row["final_status"],
            "is_anomaly":   bool(row["is_anomaly"]),
            "if_anomaly":   bool(row["if_anomaly"]),
            "ae_anomaly":   bool(row["ae_anomaly"]),
            "probabilities": prob_cols,
        }
    elif isinstance(flow_data, list):
        df_raw  = pd.DataFrame(flow_data)
        results = predict(df_raw, artifacts)
        output  = []
        for _, row in results.iterrows():
            prob_cols = {k.replace("prob_", ""): float(v)
                         for k, v in row.items() if k.startswith("prob_")}
            output.append({
                "prediction":   row["prediction"],
                "confidence":   float(row["confidence"]),
                "final_status": row["final_status"],
                "is_anomaly":   bool(row["is_anomaly"]),
                "if_anomaly":   bool(row["if_anomaly"]),
                "ae_anomaly":   bool(row["ae_anomaly"]),
                "probabilities": prob_cols,
            })
        return output
    else:
        raise TypeError(f"flow_data must be dict or list, got {type(flow_data)}")


# ─────────────────────────────────────────────────────────────────────────────
# 9. DEMO
# ─────────────────────────────────────────────────────────────────────────────

def run_demo(artifacts: IDSArtifacts):
    """
    Run a demonstration with realistic synthetic flow records.

    Each record is crafted to look like a specific attack type.
    """
    print("\n" + "=" * 65)
    print("INFERENCE DEMO -- Synthetic Flow Samples")
    print("=" * 65)

    records = {
        "Normal_HTTP_GET": {
            "Destination Port": 80, "Flow Duration": 500_000,
            "Total Fwd Packets": 5, "Total Length of Fwd Packets": 2000,
            "Flow Bytes/s": 20_000, "Flow Packets/s": 18,
            "SYN Flag Count": 1, "FIN Flag Count": 1,
            "ACK Flag Count": 8, "PSH Flag Count": 2,
            "Average Packet Size": 400,
            "Init_Win_bytes_forward": 65535,
        },
        "SYN_Flood_DDoS": {
        # Required features (all 52)
        "Destination Port": 80,
        "Flow Duration": 50,
        "Total Fwd Packets": 5000,
        "Total Length of Fwd Packets": 320000,
        "Fwd Packet Length Max": 64,
        "Fwd Packet Length Min": 64,
        "Fwd Packet Length Mean": 64,
        "Fwd Packet Length Std": 0,
        "Bwd Packet Length Max": 0,
        "Bwd Packet Length Min": 0,
        "Bwd Packet Length Mean": 0,
        "Bwd Packet Length Std": 0,
        "Flow Bytes/s": 6400000,
        "Flow Packets/s": 100000,
        "Flow IAT Mean": 0.01,
        "Flow IAT Std": 0.005,
        "Flow IAT Max": 0.02,
        "Flow IAT Min": 0.001,
        "Fwd IAT Total": 50,
        "Fwd IAT Mean": 0.01,
        "Fwd IAT Std": 0.005,
        "Fwd IAT Max": 0.02,
        "Fwd IAT Min": 0.001,
        "Bwd IAT Total": 0,
        "Bwd IAT Mean": 0,
        "Bwd IAT Std": 0,
        "Bwd IAT Max": 0,
        "Bwd IAT Min": 0,
        "Fwd Header Length": 320000,
        "Bwd Header Length": 0,
        "Fwd Packets/s": 100000,
        "Bwd Packets/s": 0,
        "Min Packet Length": 64,
        "Max Packet Length": 64,
        "Packet Length Mean": 64,
        "Packet Length Std": 0,
        "Packet Length Variance": 0,
        "FIN Flag Count": 0,
        "SYN Flag Count": 5000,
        "RST Flag Count": 0,
        "PSH Flag Count": 0,
        "ACK Flag Count": 0,
        "URG Flag Count": 0,
        "Average Packet Size": 64,
        "Subflow Fwd Bytes": 320000,
        "Init_Win_bytes_forward": 65535,
        "Init_Win_bytes_backward": 0,
        "act_data_pkt_fwd": 0,
        "min_seg_size_forward": 64,
        "Active Mean": 0.01,
        "Active Max": 0.02,
        "Active Min": 0.001,
        "Idle Mean": 0,
        "Idle Max": 0,
        "Idle Min": 0,
        },
        "SSH_BruteForce": {
            "Destination Port": 22, "Flow Duration": 30_000_000,
            "Total Fwd Packets": 1000, "Total Length of Fwd Packets": 64_000,
            "Flow Bytes/s": 2133, "Flow Packets/s": 33,
            "SYN Flag Count": 1000, "FIN Flag Count": 1000,
            "ACK Flag Count": 2000, "RST Flag Count": 100,
            "Average Packet Size": 64,
        },
        "PortScan": {
            "Destination Port": 0, "Flow Duration": 100,
            "Total Fwd Packets": 1, "Total Length of Fwd Packets": 40,
            "Flow Bytes/s": 400_000, "Flow Packets/s": 10_000,
            "SYN Flag Count": 1, "FIN Flag Count": 0,
            "ACK Flag Count": 0, "PSH Flag Count": 0,
            "Average Packet Size": 40,
        },
        "DoS_Hulk": {
            "Destination Port": 80, "Flow Duration": 100_000,
            "Total Fwd Packets": 500, "Total Length of Fwd Packets": 750_000,
            "Flow Bytes/s": 7_500_000, "Flow Packets/s": 5_000,
            "SYN Flag Count": 0, "FIN Flag Count": 0,
            "ACK Flag Count": 500, "PSH Flag Count": 500,
            "Average Packet Size": 1500,
        },
        "Botnet_C2": {
            "Destination Port": 6667, "Flow Duration": 3_600_000_000,
            "Total Fwd Packets": 10, "Total Length of Fwd Packets": 640,
            "Flow Bytes/s": 10, "Flow Packets/s": 0.003,
            "SYN Flag Count": 1, "FIN Flag Count": 0,
            "ACK Flag Count": 10, "PSH Flag Count": 8,
            "Average Packet Size": 64,
        },
    }

    df_demo = pd.DataFrame.from_dict(records, orient="index")
    results = predict(df_demo, artifacts)

    print(f"\n{'Sample':<22s}  {'Prediction':<14s}  {'Status':<14s}  "
          f"{'Confidence':>12}  {'Anomaly':<8}")
    print("─" * 80)
    for idx in results.index:
        r    = results.loc[idx]
        print(f"  {idx:<22s}  {r['prediction']:<14s}  {r['final_status']:<14s}  "
              f"{r['confidence']:>12.4f}  "
              f"{'YES' if r['is_anomaly'] else 'no':<8}")

    print("\nFull probability breakdown:")
    prob_cols = [c for c in results.columns if c.startswith("prob_")]
    pd.set_option("display.float_format", "{:.4f}".format)
    print(results[["prediction", "confidence", "final_status",
                   "is_anomaly"] + prob_cols].to_string())

    return results


# ─────────────────────────────────────────────────────────────────────────────
# 10. MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="IDS Dual-Layer Inference Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python inference.py --demo
  python inference.py --input flows.csv
  python inference.py --cicflow cicflowmeter_output.csv --output preds.csv
  python inference.py --zeek /var/log/zeek/conn.log --output zeek_preds.csv
  python inference.py --artifact_dir /my/models --demo
        """,
    )
    parser.add_argument("--input",        help="Generic CSV with flow features")
    parser.add_argument("--cicflow",      help="CICFlowMeter output CSV")
    parser.add_argument("--zeek",         help="Zeek conn.log file")
    parser.add_argument("--output",       default="predictions.csv",
                        help="Output CSV path (default: predictions.csv)")
    parser.add_argument("--demo",         action="store_true",
                        help="Run demo with synthetic data")
    parser.add_argument("--artifact_dir", default=ARTIFACT_DIR,
                        help="Directory containing model artifacts")
    parser.add_argument("--model_name",   default=None,
                        help="Use specific model (e.g. 'RandomForest' -> model_RandomForest.pkl)")
    args = parser.parse_args()

    # ── Load artifacts ───────────────────────────────────────────────────────
    artifact_dir = args.artifact_dir
    requested_model = None
    if args.model_name:
        requested_model = f"model_{args.model_name}.pkl"

    model_path = resolve_model_path(artifact_dir, requested_model)

    artifacts = IDSArtifacts(
        model_path      = model_path,
        scaler_path     = os.path.join(artifact_dir, "scaler.pkl"),
        le_path         = os.path.join(artifact_dir, "label_encoder.pkl"),
        feat_path       = os.path.join(artifact_dir, "feature_columns.json"),
        iforest_path    = os.path.join(artifact_dir, "iforest.pkl"),
        ae_path         = os.path.join(artifact_dir, "autoencoder.pkl"),
        thresholds_path = os.path.join(artifact_dir, "anomaly_thresholds.json"),
    )

    # ── Run inference ────────────────────────────────────────────────────────
    if args.demo or (not args.input and not args.cicflow and not args.zeek):
        run_demo(artifacts)

    if args.cicflow:
        df = load_cicflowmeter_csv(args.cicflow)
        results = predict(df, artifacts)
        out = pd.concat([df.reset_index(drop=True),
                         results.reset_index(drop=True)], axis=1)
        out.to_csv(args.output, index=False)
        print(f"\nPredictions saved -> {args.output}")
        print(results["final_status"].value_counts().to_string())

    if args.input:
        predict_csv(args.input, args.output, artifacts)

    if args.zeek:
        predict_zeek_log(args.zeek, args.output, artifacts)


if __name__ == "__main__":
    main()