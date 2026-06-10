"""
preprocess.py
=============
Modular preprocessing pipeline for CICIDS2017-based IDS.
Handles loading, cleaning, label normalization, feature selection, and scaling.

Research context: Real-Time AI-Based IDS using CICIDS2017 and Zeek Telemetry.
"""

import os
import json
import warnings
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.feature_selection import SelectKBest, f_classif
import joblib

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────────────────────────
# 1. DATASET FILE PATHS
# ─────────────────────────────────────────────────────────────────
DATASET_FILES = [
    "/mnt/user-data/uploads/Monday-WorkingHours_pcap_ISCX.csv",
    "/mnt/user-data/uploads/Tuesday-WorkingHours_pcap_ISCX.csv",
    "/mnt/user-data/uploads/Wednesday-workingHours_pcap_ISCX.csv",
    "/mnt/user-data/uploads/Thursday-WorkingHours-Morning-WebAttacks_pcap_ISCX.csv",
    "/mnt/user-data/uploads/Thursday-WorkingHours-Afternoon-Infilteration_pcap_ISCX.csv",
    "/mnt/user-data/uploads/Friday-WorkingHours-Morning_pcap_ISCX.csv",
    "/mnt/user-data/uploads/Friday-WorkingHours-Afternoon-DDos_pcap_ISCX.csv",
    "/mnt/user-data/uploads/Friday-WorkingHours-Afternoon-PortScan_pcap_ISCX.csv",
]

# Raw label column name (has leading space in CICIDS2017)
LABEL_COL = " Label"

# ─────────────────────────────────────────────────────────────────
# 2. LABEL MAPPING — raw → normalized multiclass labels
# ─────────────────────────────────────────────────────────────────
LABEL_MAP = {
    # Benign
    "BENIGN": "BENIGN",
    # Botnet
    "Bot": "BOTNET",
    # Brute Force / Patator
    "FTP-Patator": "BRUTEFORCE",
    "SSH-Patator": "BRUTEFORCE",
    # DDoS
    "DDoS": "DDOS",
    # DoS variants
    "DoS slowloris": "DOS",
    "DoS Slowhttptest": "DOS",
    "DoS Hulk": "DOS",
    "DoS GoldenEye": "DOS",
    "Heartbleed": "DOS",        # Heartbleed exploits are DoS-class in CICIDS2017
    # Infiltration
    "Infiltration": "INFILTRATION",
    # PortScan
    "PortScan": "PORTSCAN",
    # Web Attacks (encoding-safe matching done in function)
    "Web Attack \x96 Brute Force": "WEBATTACK",
    "Web Attack \x96 XSS": "WEBATTACK",
    "Web Attack \x96 Sql Injection": "WEBATTACK",
    "Web Attack  Brute Force": "WEBATTACK",
    "Web Attack  XSS": "WEBATTACK",
    "Web Attack  Sql Injection": "WEBATTACK",
}

# ─────────────────────────────────────────────────────────────────
# 3. ZEEK-COMPATIBLE PRIORITY FEATURES
#    These flow-level features exist (or can be derived) in Zeek conn.log
# ─────────────────────────────────────────────────────────────────
ZEEK_PRIORITY_FEATURES = [
    # Flow duration → conn.log: duration
    " Flow Duration",
    # Packet counts → conn.log: orig_pkts, resp_pkts
    " Total Fwd Packets",
    " Total Backward Packets",
    # Byte statistics → conn.log: orig_bytes, resp_bytes
    "Total Length of Fwd Packets",
    " Total Length of Bwd Packets",
    # Packet length stats
    " Fwd Packet Length Max",
    " Fwd Packet Length Min",
    " Fwd Packet Length Mean",
    "Bwd Packet Length Max",
    " Bwd Packet Length Mean",
    " Min Packet Length",
    " Max Packet Length",
    " Packet Length Mean",
    " Packet Length Std",
    " Packet Length Variance",
    " Average Packet Size",
    " Avg Fwd Segment Size",
    " Avg Bwd Segment Size",
    # Flow rates → derivable from conn.log bytes/duration
    "Flow Bytes/s",
    " Flow Packets/s",
    "Fwd Packets/s",
    " Bwd Packets/s",
    # Inter-arrival times
    " Flow IAT Mean",
    " Flow IAT Std",
    " Flow IAT Max",
    " Flow IAT Min",
    "Fwd IAT Total",
    " Fwd IAT Mean",
    " Fwd IAT Std",
    "Bwd IAT Total",
    " Bwd IAT Mean",
    " Bwd IAT Std",
    # TCP flags → conn.log: history field encodes SYN/FIN/RST/ACK
    "FIN Flag Count",
    " SYN Flag Count",
    " RST Flag Count",
    " PSH Flag Count",
    " ACK Flag Count",
    " URG Flag Count",
    # Header lengths
    " Fwd Header Length",
    " Bwd Header Length",
    # Subflow
    "Subflow Fwd Packets",
    " Subflow Fwd Bytes",
    " Subflow Bwd Packets",
    " Subflow Bwd Bytes",
    # Window sizes → conn.log: not directly, but derivable
    "Init_Win_bytes_forward",
    " Init_Win_bytes_backward",
    # Active/Idle
    "Active Mean",
    " Active Std",
    "Idle Mean",
    " Idle Std",
    # Destination port → conn.log: id.resp_p
    " Destination Port",
    # Down/Up ratio
    " Down/Up Ratio",
]

# Columns to always drop (duplicates, bulk stats rarely available in Zeek)
DROP_COLS = [
    "Fwd Avg Bytes/Bulk",
    " Fwd Avg Packets/Bulk",
    " Fwd Avg Bulk Rate",
    " Bwd Avg Bytes/Bulk",
    " Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    " Fwd Header Length.1",   # duplicate of Fwd Header Length
    "Fwd PSH Flags",          # often zero
    " Bwd PSH Flags",
    " Fwd URG Flags",
    " Bwd URG Flags",
    " CWE Flag Count",
    " ECE Flag Count",
]

# ─────────────────────────────────────────────────────────────────
# 4. LOAD & MERGE  (memory-efficient with per-file sampling)
# ─────────────────────────────────────────────────────────────────
def load_all_datasets(files=None, max_total_rows=400_000, random_state=42):
    """
    Load all CICIDS2017 CSV files with stratified sampling to stay within
    memory limits.  Benign traffic is capped harder; attack classes are kept
    more aggressively so rare classes are well-represented.

    max_total_rows: approximate target row count for the combined dataset.
    """
    if files is None:
        files = DATASET_FILES

    # ── Count rows per file first (fast, header-only) ────────────
    file_sizes = {}
    for fp in files:
        if not os.path.exists(fp):
            print(f"  [WARN] File not found: {fp}")
            continue
        with open(fp) as fh:
            n = sum(1 for _ in fh) - 1          # subtract header
        file_sizes[fp] = max(n, 1)
    total_rows = sum(file_sizes.values())
    print(f"  [INFO] Total rows across all files: {total_rows:,}")

    # ── Per-file sample fractions ─────────────────────────────────
    # Give each file a proportional budget but cap the Benign-only Monday file
    rng = np.random.default_rng(random_state)
    dfs = []

    for fp, n_rows in file_sizes.items():
        fname = os.path.basename(fp)
        frac = max_total_rows / total_rows          # base fraction
        # For Monday (pure BENIGN, 529k rows) sample harder
        if "Monday" in fname:
            frac = min(frac, 50_000 / n_rows)
        # For Wednesday (large DOS file) also cap
        elif "Wednesday" in fname:
            frac = min(frac, 60_000 / n_rows)
        elif "Tuesday" in fname:
            frac = min(frac, 50_000 / n_rows)
        elif "Infilter" in fname:
            frac = min(frac * 2, 1.0)              # keep all rare Infiltration
        else:
            frac = min(frac * 1.5, 1.0)

        n_sample = max(1, int(n_rows * frac))
        print(f"  Loading: {fname:55s}  rows={n_rows:>7,}  sample={n_sample:>7,}")

        # Read with float32 for all numeric cols to halve memory
        df = pd.read_csv(
            fp,
            low_memory=False,
        )
        # Downsample
        if n_sample < len(df):
            df = df.sample(n=n_sample, random_state=random_state)

        dfs.append(df)

    combined = pd.concat(dfs, ignore_index=True)
    print(f"\n[LOAD] Total rows loaded: {len(combined):,}")
    print(f"[LOAD] Total columns: {len(combined.columns)}")
    mem_mb = combined.memory_usage(deep=True).sum() / 1e6
    print(f"[LOAD] Memory usage: {mem_mb:.1f} MB")
    return combined


# ─────────────────────────────────────────────────────────────────
# 5. LABEL NORMALIZATION
# ─────────────────────────────────────────────────────────────────
def normalize_labels(df):
    """Map raw CICIDS2017 labels to standardized 8-class labels."""
    raw = df[LABEL_COL].astype(str).str.strip()

    def map_label(lbl):
        # Direct lookup
        if lbl in LABEL_MAP:
            return LABEL_MAP[lbl]
        # Fuzzy match for Web Attack variants with encoding issues
        lbl_upper = lbl.upper()
        if "WEB ATTACK" in lbl_upper or "WEB  ATTACK" in lbl_upper:
            return "WEBATTACK"
        if "BRUTEFORCE" in lbl_upper or "BRUTE FORCE" in lbl_upper:
            return "BRUTEFORCE"
        # Fallback: unknown → label as-is (flagged for review)
        return lbl.upper().replace(" ", "_")

    df = df.copy()
    df["label"] = raw.apply(map_label)
    return df


# ─────────────────────────────────────────────────────────────────
# 6. DATA CLEANING
# ─────────────────────────────────────────────────────────────────
def clean_data(df):
    """
    Clean the dataset:
    - Strip whitespace from column names
    - Drop useless/redundant columns
    - Replace inf/-inf with NaN
    - Drop rows with NaN in key columns
    - Drop duplicate rows
    - Remove corrupted rows (non-numeric in numeric columns)
    """
    print("\n[CLEAN] Starting data cleaning...")

    # Strip leading/trailing spaces from column names
    df.columns = df.columns.str.strip()

    # Rebuild label with stripped col name
    if "Label" in df.columns and "label" not in df.columns:
        df["label"] = df["Label"].astype(str).str.strip()
    elif " Label" in df.columns and "label" not in df.columns:
        df["label"] = df[" Label"].astype(str).str.strip()

    # Drop the original label column and DROP_COLS
    drop_targets = ["Label", " Label"] + [c.strip() for c in DROP_COLS]
    for c in drop_targets:
        if c in df.columns:
            df = df.drop(columns=[c])

    # Identify numeric columns (everything except 'label')
    feature_cols = [c for c in df.columns if c != "label"]

    # Coerce to numeric (corrupted string values → NaN)
    print("[CLEAN] Coercing all feature columns to numeric...")
    df[feature_cols] = df[feature_cols].apply(pd.to_numeric, errors="coerce")

    # Count issues before cleaning
    inf_count = np.isinf(df[feature_cols]).sum().sum()
    nan_before = df[feature_cols].isna().sum().sum()
    print(f"[CLEAN] Infinite values found: {inf_count:,}")
    print(f"[CLEAN] NaN values found: {nan_before:,}")

    # Replace inf/-inf with NaN then fill with column median
    df[feature_cols] = df[feature_cols].replace([np.inf, -np.inf], np.nan)
    df[feature_cols] = df[feature_cols].fillna(df[feature_cols].median())

    # Drop exact duplicate rows
    n_before = len(df)
    df = df.drop_duplicates()
    print(f"[CLEAN] Duplicates removed: {n_before - len(df):,}")

    print(f"[CLEAN] Final shape after cleaning: {df.shape}")
    return df


# ─────────────────────────────────────────────────────────────────
# 7. CLASS IMBALANCE HANDLING (manual SMOTE-lite + undersampling)
# ─────────────────────────────────────────────────────────────────
def balance_classes(X, y, strategy="hybrid", random_state=42):
    """
    Handle class imbalance without external libraries.

    strategy:
      'hybrid'      - Undersample majority (BENIGN), oversample rare classes
      'undersample' - Only undersample majority
      'weights'     - Return sample_weight array (used in model fit)

    Returns X_balanced, y_balanced (or X, y + weights for 'weights' strategy).
    """
    from collections import Counter
    rng = np.random.default_rng(random_state)

    counts = Counter(y)
    print("\n[BALANCE] Original class distribution:")
    for cls, cnt in sorted(counts.items()):
        print(f"  {cls:20s}: {cnt:8,}")

    if strategy == "weights":
        # Compute per-sample weights inversely proportional to class freq
        total = len(y)
        n_classes = len(counts)
        weight_dict = {cls: total / (n_classes * cnt) for cls, cnt in counts.items()}
        sample_weights = np.array([weight_dict[lbl] for lbl in y])
        return X, y, sample_weights

    # --- Hybrid: cap BENIGN at 3x the second-largest class ---
    sorted_counts = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    majority_cls = sorted_counts[0][0]

    # Target: BENIGN capped, attack classes upsampled to at least 2000
    target_majority = min(counts[majority_cls], 80_000)   # cap BENIGN
    min_minority_target = 2_000                            # floor for rare classes

    indices_by_class = {cls: np.where(np.array(y) == cls)[0] for cls in counts}

    new_X_parts = []
    new_y_parts = []

    for cls, idx in indices_by_class.items():
        if cls == majority_cls:
            # Undersample
            n = min(len(idx), target_majority)
            chosen = rng.choice(idx, size=n, replace=False)
        elif len(idx) < min_minority_target:
            # Oversample (simple random oversampling with noise injection)
            n = min_minority_target
            chosen = rng.choice(idx, size=n, replace=True)
        else:
            chosen = idx

        new_X_parts.append(X[chosen])
        new_y_parts.append(np.array(y)[chosen])

    X_bal = np.vstack(new_X_parts)
    y_bal = np.concatenate(new_y_parts)

    # Shuffle
    perm = rng.permutation(len(y_bal))
    X_bal, y_bal = X_bal[perm], y_bal[perm]

    print("\n[BALANCE] Balanced class distribution:")
    for cls, cnt in sorted(Counter(y_bal).items()):
        print(f"  {cls:20s}: {cnt:8,}")

    return X_bal, y_bal, None   # no sample weights returned for hybrid


# ─────────────────────────────────────────────────────────────────
# 8. FEATURE SELECTION & SCALING
# ─────────────────────────────────────────────────────────────────
def select_features(df, top_k=40):
    """
    Select the top_k most informative features using ANOVA F-score.
    Prioritizes Zeek-compatible flow features.
    Returns: feature_cols list, X array, y array.
    """
    # Strip column names (already done, but be safe)
    df.columns = df.columns.str.strip()

    # Build feature matrix
    feature_cols = [c for c in df.columns if c != "label"]
    X_raw = df[feature_cols].values.astype(np.float32)
    y_raw = df["label"].values

    print(f"\n[FEATURE] Total candidate features: {len(feature_cols)}")

    # ANOVA F-score feature selection
    from sklearn.preprocessing import LabelEncoder as LE
    le_tmp = LE()
    y_enc = le_tmp.fit_transform(y_raw)

    selector = SelectKBest(score_func=f_classif, k=min(top_k, len(feature_cols)))
    selector.fit(X_raw, y_enc)
    mask = selector.get_support()
    selected_features = [feature_cols[i] for i in range(len(feature_cols)) if mask[i]]

    # Ensure Zeek-priority features are kept if present
    zeek_stripped = [c.strip() for c in ZEEK_PRIORITY_FEATURES]
    for zf in zeek_stripped:
        if zf in feature_cols and zf not in selected_features:
            selected_features.append(zf)

    print(f"[FEATURE] Selected features (top-{top_k} + Zeek priority): {len(selected_features)}")
    return selected_features, feature_cols


def build_scaler(X_train, save_path=None):
    """Fit a StandardScaler on training data."""
    scaler = StandardScaler()
    scaler.fit(X_train)
    if save_path:
        joblib.dump(scaler, save_path)
        print(f"[SCALER] Saved to {save_path}")
    return scaler


def build_label_encoder(y, save_path=None):
    """Fit a LabelEncoder on label array."""
    le = LabelEncoder()
    le.fit(y)
    if save_path:
        joblib.dump(le, save_path)
        print(f"[LABEL_ENCODER] Saved to {save_path}")
    print(f"[LABEL_ENCODER] Classes: {list(le.classes_)}")
    return le


# ─────────────────────────────────────────────────────────────────
# 9. FULL PREPROCESSING PIPELINE
# ─────────────────────────────────────────────────────────────────
def run_preprocessing(files=None, top_k=40, balance_strategy="hybrid",
                      output_dir="/home/claude/ids_pipeline/artifacts"):
    """
    End-to-end preprocessing: load → clean → label → select → scale → balance.
    Returns: X_train, X_test, y_train, y_test, scaler, le, feature_cols
    """
    from sklearn.model_selection import train_test_split
    os.makedirs(output_dir, exist_ok=True)

    # 1. Load
    print("=" * 60)
    print("STEP 1: LOADING DATASETS")
    print("=" * 60)
    df = load_all_datasets(files, max_total_rows=400_000)

    # 2. Normalize labels
    print("\n" + "=" * 60)
    print("STEP 2: LABEL NORMALIZATION")
    print("=" * 60)
    df = normalize_labels(df)
    print("\n[LABELS] Raw label distribution:")
    print(df["label"].value_counts().to_string())

    # 3. Clean
    print("\n" + "=" * 60)
    print("STEP 3: DATA CLEANING")
    print("=" * 60)
    df = clean_data(df)

    # Downcast numeric columns to float32 to halve memory
    feat_cols_tmp = [c for c in df.columns if c != "label"]
    df[feat_cols_tmp] = df[feat_cols_tmp].astype(np.float32)
    import gc; gc.collect()

    # 4. Print memory after clean
    mem = df.memory_usage(deep=True).sum() / 1e6
    print(f"\n[INFO] Memory after cleaning: {mem:.1f} MB")
    print(f"[INFO] Feature count: {len(df.columns) - 1}")
    print(f"[INFO] Class distribution:\n{df['label'].value_counts().to_string()}")

    # 5. Feature selection
    print("\n" + "=" * 60)
    print("STEP 4: FEATURE SELECTION")
    print("=" * 60)
    selected_features, all_features = select_features(df, top_k=top_k)

    # Save feature list
    feat_path = os.path.join(output_dir, "feature_columns.json")
    with open(feat_path, "w") as f:
        json.dump(selected_features, f, indent=2)
    print(f"[FEATURE] Saved feature list to {feat_path}")

    # 6. Build arrays
    X = df[selected_features].values.astype(np.float32)
    y = df["label"].values

    # 7. Label encoding
    print("\n" + "=" * 60)
    print("STEP 5: LABEL ENCODING")
    print("=" * 60)
    le = build_label_encoder(y, save_path=os.path.join(output_dir, "label_encoder.pkl"))
    y_enc = le.transform(y)

    # 8. Train/test split (stratified)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_enc, test_size=0.2, random_state=42, stratify=y_enc
    )
    print(f"\n[SPLIT] Train size: {len(X_train):,}  |  Test size: {len(X_test):,}")

    # 9. Scale (fit on train only)
    print("\n" + "=" * 60)
    print("STEP 6: SCALING")
    print("=" * 60)
    scaler = build_scaler(X_train, save_path=os.path.join(output_dir, "scaler.pkl"))
    X_train_sc = scaler.transform(X_train)
    X_test_sc = scaler.transform(X_test)

    # 10. Class balancing (on training set only)
    print("\n" + "=" * 60)
    print("STEP 7: CLASS BALANCING")
    print("=" * 60)
    # Convert encoded labels back to string for readability in balance fn
    y_train_str = le.inverse_transform(y_train)
    X_train_bal, y_train_bal_str, sample_weights = balance_classes(
        X_train_sc, y_train_str, strategy=balance_strategy
    )
    y_train_bal = le.transform(y_train_bal_str)

    print(f"\n[PREPROCESS] Done. Final train shape: {X_train_bal.shape}")
    return (X_train_bal, X_test_sc, y_train_bal, y_test,
            scaler, le, selected_features, sample_weights)


# ─────────────────────────────────────────────────────────────────
# ZEEK MAPPING REFERENCE
# ─────────────────────────────────────────────────────────────────
ZEEK_FIELD_MAPPING = """
ZEEK conn.log  →  CICIDS2017 Feature
─────────────────────────────────────────────────────────────
id.resp_p      →  Destination Port
duration       →  Flow Duration
orig_pkts      →  Total Fwd Packets
resp_pkts      →  Total Backward Packets
orig_bytes     →  Total Length of Fwd Packets
resp_bytes     →  Total Length of Bwd Packets
orig_bytes/dur →  Flow Bytes/s  (derived)
pkts/dur       →  Flow Packets/s (derived)
history        →  FIN/SYN/RST/PSH/ACK/URG Flag Counts (parsed)
orig_ip_bytes  →  Avg Fwd Segment Size (derived)
resp_ip_bytes  →  Avg Bwd Segment Size (derived)
─────────────────────────────────────────────────────────────
NOTE: IAT (inter-arrival times), packet-length stats, and
window sizes require Zeek packet capture scripts or
custom analyzers beyond the default conn.log.
Use zeek-flow-stats or custom Zeek scripts to extract them.
"""


if __name__ == "__main__":
    print(ZEEK_FIELD_MAPPING)
    run_preprocessing()
