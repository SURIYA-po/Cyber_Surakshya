"""
preprocess.py
=============
NEW PIPELINE — built for the Kaggle "cicids2017-cleaned-and-preprocessed" dataset.

Dataset:  data/cicids2017_cleaned.csv
          53 columns (52 numeric features + 'Attack Type' label column)
          2,520,751 rows | 7 attack classes (already clean — no inf/NaN)

This module handles:
  1. Loading the pre-cleaned CSV with memory-efficient chunking / sampling
  2. Label normalisation  →  6 attack classes + BENIGN
  3. Light cleaning pass  (guards for any residual NaN / inf)
  4. Stratified train/test split
  5. StandardScaler fit on train only
  6. SMOTE-free class balancing (hybrid under+oversample)
  7. Feature selection (ANOVA F + Mutual Information)
  8. Artifact saving: scaler.pkl, label_encoder.pkl, feature_columns.json

Runtime preprocessing for CICFlowMeter CSV / Zeek conn.log is in inference.py.
"""

from __future__ import annotations

import gc
import json
import os
import warnings
from collections import Counter
from typing import Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_selection import SelectKBest, f_classif, mutual_info_classif
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────────────────────────────────────
# PATHS & CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, "data", "cicids2017_cleaned.csv")

# Label column in the cleaned Kaggle dataset
LABEL_COL = "Attack Type"

# ─────────────────────────────────────────────────────────────────────────────
# LABEL MAPPING  (Kaggle cleaned dataset → normalised 7-class labels)
# ─────────────────────────────────────────────────────────────────────────────
# The dataset already has clean labels with no leading spaces.
LABEL_MAP: dict[str, str] = {
    "Normal Traffic":  "BENIGN",
    "DoS":             "DOS",
    "DDoS":            "DDOS",
    "Port Scanning":   "PORTSCAN",
    "Brute Force":     "BRUTEFORCE",
    "Web Attacks":     "WEBATTACK",
    "Bots":            "BOTNET",
}

# Ordered canonical classes
CLASS_ORDER = ["BENIGN", "BOTNET", "BRUTEFORCE", "DDOS", "DOS", "PORTSCAN", "WEBATTACK"]

# ─────────────────────────────────────────────────────────────────────────────
# ZEEK-COMPATIBLE FEATURE PRIORITY LIST
# (used to ensure Zeek-derivable features survive feature selection)
# ─────────────────────────────────────────────────────────────────────────────
ZEEK_PRIORITY_FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Length of Fwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "FIN Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "Average Packet Size",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "Fwd IAT Total",
    "Bwd IAT Total",
    "Fwd Header Length",
    "Bwd Header Length",
    "Subflow Fwd Bytes",
]

# Columns to always drop (bulk/rarely-available in live telemetry)
DROP_COLS: list[str] = []  # dataset is already clean; kept for extensibility


# ─────────────────────────────────────────────────────────────────────────────
# 1. LOAD
# ─────────────────────────────────────────────────────────────────────────────

def load_dataset(
    path: str = DATA_PATH,
    max_rows: int = 500_000,
    random_state: int = 42,
) -> pd.DataFrame:
    """
    Load the pre-cleaned CICIDS2017 CSV with stratified row-capping.

    The dataset has 2.5 M rows.  We default to 500 k rows so that training
    runs in reasonable time on a standard machine (8–16 GB RAM).
    Raise max_rows to 0 (or a very large number) to load everything.

    Strategy
    --------
    * Count rows per label first (single fast pass).
    * Sample proportionally, but cap BENIGN hard and oversample tiny classes.
    * Returns a shuffled DataFrame.
    """
    print("=" * 65)
    print("STEP 1: LOADING DATASET")
    print("=" * 65)
    print(f"  Source : {path}")
    print(f"  Target : ≤{max_rows:,} rows")

    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Dataset not found at: {path}\n"
            "Place cicids2017_cleaned.csv inside the data/ folder."
        )

    # ── fast label-count pass ───────────────────────────────────────
    print("  Counting label distribution (fast pass)…")
    label_counts: Counter = Counter()
    with open(path, encoding="utf-8", errors="replace") as fh:
        header = fh.readline().strip().split(",")
        lbl_idx = header.index(LABEL_COL)
        for line in fh:
            parts = line.rstrip("\n").split(",")
            if len(parts) > lbl_idx:
                label_counts[parts[lbl_idx]] += 1

    total = sum(label_counts.values())
    print(f"  Total rows in file : {total:,}")
    for lbl, cnt in sorted(label_counts.items(), key=lambda x: -x[1]):
        print(f"    {lbl:<25s}: {cnt:>10,}")

    if max_rows <= 0 or max_rows >= total:
        # Load everything
        df = pd.read_csv(path, low_memory=False, encoding="utf-8", encoding_errors="replace")
        print(f"\n[LOAD] Loaded all {len(df):,} rows.")
        return df.sample(frac=1, random_state=random_state).reset_index(drop=True)

    # ── per-label sampling budget ───────────────────────────────────
    rng = np.random.default_rng(random_state)

    # Targets: BENIGN capped at 120 k; minority classes kept generously
    BENIGN_CAP        = 120_000
    MINORITY_FLOOR    = 3_000
    remaining_budget  = max_rows - min(label_counts.get("Normal Traffic", 0), BENIGN_CAP)
    non_benign_total  = total - label_counts.get("Normal Traffic", 0)

    targets: dict[str, int] = {}
    for lbl, cnt in label_counts.items():
        if lbl == "Normal Traffic":
            targets[lbl] = min(cnt, BENIGN_CAP)
        else:
            prop = max(remaining_budget * cnt / max(non_benign_total, 1), MINORITY_FLOOR)
            targets[lbl] = min(cnt, int(prop))

    print(f"\n  Sampling targets:")
    for lbl, t in sorted(targets.items(), key=lambda x: -x[1]):
        print(f"    {lbl:<25s}: {t:>8,}")

    # ── single CSV pass collecting sampled rows ─────────────────────
    # Buffer rows by label; reservoir-sample to avoid loading entire file
    buffers: dict[str, list[str]] = {lbl: [] for lbl in label_counts}
    with open(path, encoding="utf-8", errors="replace") as fh:
        hdr_line = fh.readline()
        for line in fh:
            parts = line.rstrip("\n").split(",")
            if len(parts) <= lbl_idx:
                continue
            lbl = parts[lbl_idx]
            tgt = targets.get(lbl, 0)
            buf = buffers.get(lbl, [])
            n   = len(buf)
            if n < tgt:
                buf.append(line)
                buffers[lbl] = buf
            else:
                # Reservoir sampling
                j = int(rng.integers(0, n + 1))
                if j < tgt:
                    buf[j] = line
                buffers[lbl] = buf

    from io import StringIO
    all_lines = hdr_line
    for lbl, lines in buffers.items():
        all_lines += "".join(lines)

    df = pd.read_csv(
        StringIO(all_lines),
        low_memory=False,
        encoding="utf-8",
    )
    df = df.sample(frac=1, random_state=random_state).reset_index(drop=True)
    print(f"\n[LOAD] Sampled {len(df):,} rows | {len(df.columns)} columns")
    return df


# ─────────────────────────────────────────────────────────────────────────────
# 2. LABEL NORMALISATION
# ─────────────────────────────────────────────────────────────────────────────

def normalize_labels(df: pd.DataFrame) -> pd.DataFrame:
    """Map raw labels to canonical 7-class labels.  Drop unmapped rows."""
    df = df.copy()
    raw = df[LABEL_COL].astype(str).str.strip()

    def _map(lbl: str) -> str:
        if lbl in LABEL_MAP:
            return LABEL_MAP[lbl]
        lbl_u = lbl.upper()
        if "NORMAL" in lbl_u:
            return "BENIGN"
        if "DOS" in lbl_u and "DDOS" not in lbl_u:
            return "DOS"
        if "DDOS" in lbl_u or "DISTRIBUTED" in lbl_u:
            return "DDOS"
        if "SCAN" in lbl_u or "PORT" in lbl_u:
            return "PORTSCAN"
        if "BRUTE" in lbl_u or "PATATOR" in lbl_u:
            return "BRUTEFORCE"
        if "WEB" in lbl_u or "SQL" in lbl_u or "XSS" in lbl_u:
            return "WEBATTACK"
        if "BOT" in lbl_u:
            return "BOTNET"
        return "__UNKNOWN__"

    df["label"] = raw.apply(_map)
    unknown_mask = df["label"] == "__UNKNOWN__"
    if unknown_mask.sum() > 0:
        print(f"  [WARN] Dropping {unknown_mask.sum():,} rows with unmapped labels.")
        df = df[~unknown_mask]

    df = df.drop(columns=[LABEL_COL])
    print(f"[LABELS] Normalised distribution:")
    for cls, cnt in df["label"].value_counts().items():
        print(f"  {cls:<15s}: {cnt:>10,}")
    return df


# ─────────────────────────────────────────────────────────────────────────────
# 3. CLEANING  (light guard — dataset is pre-cleaned)
# ─────────────────────────────────────────────────────────────────────────────

def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    """
    Light cleaning pass:
      - Strip column-name whitespace
      - Drop DROP_COLS
      - Coerce to numeric, replace inf/NaN with column median
      - Drop duplicate rows
    """
    print("\n[CLEAN] Cleaning data…")
    df = df.copy()
    df.columns = df.columns.str.strip()

    # Drop unwanted columns
    for c in DROP_COLS:
        cs = c.strip()
        if cs in df.columns:
            df = df.drop(columns=[cs])

    feature_cols = [c for c in df.columns if c != "label"]

    # Coerce to numeric
    df[feature_cols] = df[feature_cols].apply(pd.to_numeric, errors="coerce")

    # Replace inf
    n_inf = np.isinf(df[feature_cols].values).sum()
    if n_inf:
        print(f"  Replacing {n_inf:,} inf values with column median.")
    df[feature_cols] = df[feature_cols].replace([np.inf, -np.inf], np.nan)

    # Fill NaN with median
    n_nan = df[feature_cols].isna().sum().sum()
    if n_nan:
        print(f"  Filling {n_nan:,} NaN values with column median.")
    df[feature_cols] = df[feature_cols].fillna(df[feature_cols].median())

    # Drop duplicates
    before = len(df)
    df = df.drop_duplicates()
    print(f"  Duplicates removed: {before - len(df):,}")
    print(f"  Final shape: {df.shape}")
    return df


# ─────────────────────────────────────────────────────────────────────────────
# 4. FEATURE SELECTION
# ─────────────────────────────────────────────────────────────────────────────

def select_features(
    df: pd.DataFrame,
    top_k: int = 40,
    random_state: int = 42,
) -> tuple[list[str], list[str]]:
    """
    Combined ANOVA F-score + Mutual Information feature selection.

    Strategy
    --------
    * Compute both ANOVA-F and MI scores.
    * Average the normalised rank of each feature.
    * Select top_k features by average rank.
    * Force-include any Zeek-compatible features that are in the dataset.

    Returns: (selected_features, all_feature_cols)
    """
    print(f"\n[FEATURE] Selecting top-{top_k} features…")
    df.columns = df.columns.str.strip()
    feature_cols = [c for c in df.columns if c != "label"]

    X = df[feature_cols].values.astype(np.float32)
    le_tmp = LabelEncoder()
    y_enc  = le_tmp.fit_transform(df["label"].values)

    # ANOVA F
    sel_f = SelectKBest(score_func=f_classif, k="all")
    sel_f.fit(X, y_enc)
    scores_f = np.nan_to_num(sel_f.scores_, nan=0.0)

    # Mutual Information (subsample for speed on large datasets)
    n_mi  = min(len(X), 30_000)
    idx_mi = np.random.default_rng(random_state).choice(len(X), n_mi, replace=False)
    scores_mi = mutual_info_classif(
        X[idx_mi], y_enc[idx_mi], random_state=random_state
    )

    # Normalise and combine
    def _norm(arr):
        rng_val = arr.max() - arr.min()
        return (arr - arr.min()) / (rng_val + 1e-12)

    combined = (_norm(scores_f) + _norm(scores_mi)) / 2.0
    ranked_idx = np.argsort(combined)[::-1]

    selected = [feature_cols[i] for i in ranked_idx[:top_k]]

    # Ensure Zeek-priority features are included
    for zf in ZEEK_PRIORITY_FEATURES:
        zf_s = zf.strip()
        if zf_s in feature_cols and zf_s not in selected:
            selected.append(zf_s)
            print(f"  [Zeek+] Force-added: {zf_s}")

    print(f"  Selected {len(selected)} features "
          f"(top-{top_k} by ANOVA+MI, +Zeek priority).")
    return selected, feature_cols


# ─────────────────────────────────────────────────────────────────────────────
# 5. CLASS BALANCING
# ─────────────────────────────────────────────────────────────────────────────

def balance_classes(
    X: np.ndarray,
    y: np.ndarray,
    benign_cap:    int = 80_000,
    minority_floor: int = 2_000,
    random_state:  int = 42,
) -> tuple[np.ndarray, np.ndarray]:
    """
    Hybrid under+oversample (no external library required).

    * BENIGN is capped at benign_cap.
    * Classes with fewer than minority_floor samples are oversampled with
      Gaussian noise injection (jitter ≤ 0.5% of each feature's std-dev)
      to create slight diversity.
    * All other classes are kept as-is.
    """
    rng    = np.random.default_rng(random_state)
    counts = Counter(y.tolist())
    print("\n[BALANCE] Original class distribution:")
    for cls, cnt in sorted(counts.items()):
        print(f"  {cls:<15s}: {cnt:>10,}")

    new_X: list[np.ndarray] = []
    new_y: list[np.ndarray] = []

    for cls, cnt in counts.items():
        mask = y == cls
        Xi   = X[mask]
        yi   = y[mask]

        if cls == "BENIGN":
            # Undersample
            n   = min(cnt, benign_cap)
            idx = rng.choice(cnt, n, replace=False)
            new_X.append(Xi[idx])
            new_y.append(yi[idx])

        elif cnt < minority_floor:
            # Oversample with Gaussian jitter
            n    = minority_floor
            idx  = rng.choice(cnt, n, replace=True)
            Xover = Xi[idx].astype(np.float64)
            stds  = Xover.std(axis=0) * 0.005        # 0.5 % noise
            noise = rng.normal(0, stds, Xover.shape)
            new_X.append((Xover + noise).astype(np.float32))
            new_y.append(yi[idx])

        else:
            new_X.append(Xi)
            new_y.append(yi)

    X_bal = np.vstack(new_X)
    y_bal = np.concatenate(new_y)

    # Shuffle
    perm   = rng.permutation(len(y_bal))
    X_bal  = X_bal[perm]
    y_bal  = y_bal[perm]

    print("\n[BALANCE] Balanced class distribution:")
    for cls, cnt in sorted(Counter(y_bal.tolist()).items()):
        print(f"  {cls:<15s}: {cnt:>10,}")
    return X_bal, y_bal


# ─────────────────────────────────────────────────────────────────────────────
# 6. FULL PREPROCESSING PIPELINE
# ─────────────────────────────────────────────────────────────────────────────

def run_preprocessing(
    data_path:        str  = DATA_PATH,
    max_rows:         int  = 500_000,
    top_k:            int  = 40,
    test_size:        float = 0.20,
    random_state:     int  = 42,
    output_dir:       str  = os.path.join(BASE_DIR, "artifacts"),
    balance_strategy: str  = "hybrid",   # 'hybrid' | 'none'
) -> tuple:
    """
    Full preprocessing pipeline.

    Returns
    -------
    X_train_bal, X_test_sc, y_train_bal, y_test,
    scaler, le, selected_features
    """
    os.makedirs(output_dir, exist_ok=True)

    # 1. Load
    df = load_dataset(data_path, max_rows=max_rows, random_state=random_state)

    # 2. Normalise labels
    print("\n" + "=" * 65)
    print("STEP 2: LABEL NORMALISATION")
    print("=" * 65)
    df = normalize_labels(df)

    # 3. Clean
    print("\n" + "=" * 65)
    print("STEP 3: DATA CLEANING")
    print("=" * 65)
    df = clean_data(df)

    # Downcast to float32
    feat_tmp = [c for c in df.columns if c != "label"]
    df[feat_tmp] = df[feat_tmp].astype(np.float32)
    gc.collect()

    # 4. Feature selection
    print("\n" + "=" * 65)
    print("STEP 4: FEATURE SELECTION")
    print("=" * 65)
    selected_features, _ = select_features(df, top_k=top_k, random_state=random_state)

    feat_path = os.path.join(output_dir, "feature_columns.json")
    with open(feat_path, "w") as fh:
        json.dump(selected_features, fh, indent=2)
    print(f"  Saved feature list → {feat_path}")

    # 5. Build arrays
    X = df[selected_features].values.astype(np.float32)
    y = df["label"].values

    # 6. Label encoding
    print("\n" + "=" * 65)
    print("STEP 5: LABEL ENCODING")
    print("=" * 65)
    le = LabelEncoder()
    le.fit(sorted(set(y)))          # stable alphabetical order
    y_enc = le.transform(y)
    joblib.dump(le, os.path.join(output_dir, "label_encoder.pkl"))
    print(f"  Classes : {list(le.classes_)}")

    # 7. Train / test split (stratified)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_enc,
        test_size=test_size,
        random_state=random_state,
        stratify=y_enc,
    )
    print(f"\n[SPLIT]  Train: {len(X_train):,}  |  Test: {len(X_test):,}")

    # 8. Scaling  (fit on train only)
    print("\n" + "=" * 65)
    print("STEP 6: SCALING")
    print("=" * 65)
    scaler = StandardScaler()
    scaler.fit(X_train)
    X_train_sc = scaler.transform(X_train)
    X_test_sc  = scaler.transform(X_test)
    joblib.dump(scaler, os.path.join(output_dir, "scaler.pkl"))
    print("  StandardScaler fitted and saved.")

    # 9. Class balancing  (on training set only, in string-label space)
    if balance_strategy == "hybrid":
        print("\n" + "=" * 65)
        print("STEP 7: CLASS BALANCING")
        print("=" * 65)
        y_train_str = le.inverse_transform(y_train)
        X_train_bal, y_train_bal_str = balance_classes(
            X_train_sc, y_train_str, random_state=random_state
        )
        y_train_bal = le.transform(y_train_bal_str)
    else:
        print("[BALANCE] Skipped (balance_strategy='none').")
        X_train_bal = X_train_sc
        y_train_bal = y_train

    print(f"\n[PREPROCESS] ✓  Final train shape : {X_train_bal.shape}")
    print(f"[PREPROCESS] ✓  Final test  shape : {X_test_sc.shape}")

    return (
        X_train_bal, X_test_sc,
        y_train_bal, y_test,
        scaler, le, selected_features,
    )


# ─────────────────────────────────────────────────────────────────────────────
# ZEEK FIELD MAPPING  (reference used by inference.py)
# ─────────────────────────────────────────────────────────────────────────────

ZEEK_FIELD_MAPPING = """
ZEEK conn.log  →  CICIDS2017 Feature
─────────────────────────────────────────────────────────────────
id.resp_p      →  Destination Port
duration       →  Flow Duration         (seconds → microseconds × 1e6)
orig_pkts      →  Total Fwd Packets
resp_pkts      →  (Total Backward Packets — derived)
orig_bytes     →  Total Length of Fwd Packets
resp_bytes     →  (Total Length of Bwd Packets — derived)
orig_bytes/dur →  Flow Bytes/s          (derived)
pkts/dur       →  Flow Packets/s        (derived)
history        →  FIN/PSH/ACK Flag Counts (parsed from Zeek history string)
orig_ip_bytes  →  Subflow Fwd Bytes     (approx)
resp_ip_bytes  →  (Subflow Bwd Bytes — approx)
─────────────────────────────────────────────────────────────────
CICFlowMeter CSV columns map 1:1 to CICIDS2017 columns.
Zeek conn.log covers ~15 of the 40 selected features;
remaining features are zero-filled with graceful degradation.
─────────────────────────────────────────────────────────────────
"""

CICFLOWMETER_COL_MAP = {
    # CICFlowMeter → our feature name (strip trailing spaces already handled)
    "Destination Port":           "Destination Port",
    "Flow Duration":              "Flow Duration",
    "Total Fwd Packets":          "Total Fwd Packets",
    "Total Backward Packets":     "Total Backward Packets",   # not in cleaned ds
    "Total Length of Fwd Packets":"Total Length of Fwd Packets",
    "Total Length of Bwd Packets":"Total Length of Bwd Packets",  # not in cleaned ds
    "Fwd Packet Length Max":      "Fwd Packet Length Max",
    "Fwd Packet Length Min":      "Fwd Packet Length Min",
    "Fwd Packet Length Mean":     "Fwd Packet Length Mean",
    "Fwd Packet Length Std":      "Fwd Packet Length Std",
    "Bwd Packet Length Max":      "Bwd Packet Length Max",
    "Bwd Packet Length Min":      "Bwd Packet Length Min",
    "Bwd Packet Length Mean":     "Bwd Packet Length Mean",
    "Bwd Packet Length Std":      "Bwd Packet Length Std",
    "Flow Bytes/s":               "Flow Bytes/s",
    "Flow Packets/s":             "Flow Packets/s",
    "Flow IAT Mean":              "Flow IAT Mean",
    "Flow IAT Std":               "Flow IAT Std",
    "Flow IAT Max":               "Flow IAT Max",
    "Flow IAT Min":               "Flow IAT Min",
    "Fwd IAT Total":              "Fwd IAT Total",
    "Fwd IAT Mean":               "Fwd IAT Mean",
    "Fwd IAT Std":                "Fwd IAT Std",
    "Fwd IAT Max":                "Fwd IAT Max",
    "Fwd IAT Min":                "Fwd IAT Min",
    "Bwd IAT Total":              "Bwd IAT Total",
    "Bwd IAT Mean":               "Bwd IAT Mean",
    "Bwd IAT Std":                "Bwd IAT Std",
    "Bwd IAT Max":                "Bwd IAT Max",
    "Bwd IAT Min":                "Bwd IAT Min",
    "Fwd Header Length":          "Fwd Header Length",
    "Bwd Header Length":          "Bwd Header Length",
    "Fwd Packets/s":              "Fwd Packets/s",
    "Bwd Packets/s":              "Bwd Packets/s",
    "Min Packet Length":          "Min Packet Length",
    "Max Packet Length":          "Max Packet Length",
    "Packet Length Mean":         "Packet Length Mean",
    "Packet Length Std":          "Packet Length Std",
    "Packet Length Variance":     "Packet Length Variance",
    "FIN Flag Count":             "FIN Flag Count",
    "SYN Flag Count":             "SYN Flag Count",
    "RST Flag Count":             "RST Flag Count",
    "PSH Flag Count":             "PSH Flag Count",
    "ACK Flag Count":             "ACK Flag Count",
    "URG Flag Count":             "URG Flag Count",
    "CWE Flag Count":             "CWE Flag Count",
    "ECE Flag Count":             "ECE Flag Count",
    "Down/Up Ratio":              "Down/Up Ratio",
    "Average Packet Size":        "Average Packet Size",
    "Avg Fwd Segment Size":       "Avg Fwd Segment Size",
    "Avg Bwd Segment Size":       "Avg Bwd Segment Size",
    "Subflow Fwd Packets":        "Subflow Fwd Packets",
    "Subflow Fwd Bytes":          "Subflow Fwd Bytes",
    "Subflow Bwd Packets":        "Subflow Bwd Packets",
    "Subflow Bwd Bytes":          "Subflow Bwd Bytes",
    "Init_Win_bytes_forward":     "Init_Win_bytes_forward",
    "Init_Win_bytes_backward":    "Init_Win_bytes_backward",
    "act_data_pkt_fwd":           "act_data_pkt_fwd",
    "min_seg_size_forward":       "min_seg_size_forward",
    "Active Mean":                "Active Mean",
    "Active Std":                 "Active Std",
    "Active Max":                 "Active Max",
    "Active Min":                 "Active Min",
    "Idle Mean":                  "Idle Mean",
    "Idle Std":                   "Idle Std",
    "Idle Max":                   "Idle Max",
    "Idle Min":                   "Idle Min",
}


if __name__ == "__main__":
    print(ZEEK_FIELD_MAPPING)
    run_preprocessing()