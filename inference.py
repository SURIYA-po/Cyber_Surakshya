"""
inference.py
============
Inference pipeline for the CICIDS2017 IDS model.
Supports:
  - Single flow prediction
  - Batch CSV prediction
  - Zeek conn.log translation example

Usage:
    python inference.py --input flows.csv --output predictions.csv
    python inference.py --demo          # run demo with synthetic data
    python inference.py --zeek zeek_conn.log  # translate & predict Zeek logs
"""

import os
import sys
import json
import argparse
import warnings
import numpy as np
import pandas as pd
import joblib

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────────────────────────
# ARTIFACT PATHS
# ─────────────────────────────────────────────────────────────────
ARTIFACT_DIR = "C:/Users/ACER/Downloads/files/artifacts"
MODEL_PATH    = os.path.join(ARTIFACT_DIR, "model.pkl")
SCALER_PATH   = os.path.join(ARTIFACT_DIR, "scaler.pkl")
LE_PATH       = os.path.join(ARTIFACT_DIR, "label_encoder.pkl")
FEAT_PATH     = os.path.join(ARTIFACT_DIR, "feature_columns.json")


# ─────────────────────────────────────────────────────────────────
# LOAD ARTIFACTS
# ─────────────────────────────────────────────────────────────────
def load_artifacts(model_path=MODEL_PATH, scaler_path=SCALER_PATH,
                   le_path=LE_PATH, feat_path=FEAT_PATH):
    """Load all inference artifacts from disk."""
    print("[INFERENCE] Loading artifacts...")
    model  = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    le     = joblib.load(le_path)
    with open(feat_path) as f:
        feature_cols = json.load(f)
    print(f"  Model     : {type(model).__name__}")
    print(f"  Features  : {len(feature_cols)}")
    print(f"  Classes   : {list(le.classes_)}")
    return model, scaler, le, feature_cols


# ─────────────────────────────────────────────────────────────────
# PREPROCESSING FOR INFERENCE
# ─────────────────────────────────────────────────────────────────
def preprocess_for_inference(df_raw, feature_cols, scaler):
    """
    Align raw flow data to model feature schema, scale, return array.
    Missing columns are zero-filled.
    """
    # Strip whitespace from incoming column names
    df_raw = df_raw.copy()
    df_raw.columns = df_raw.columns.str.strip()

    # Build aligned DataFrame with expected columns
    df_aligned = pd.DataFrame(0.0, index=df_raw.index,
                               columns=[c.strip() for c in feature_cols])

    stripped_feat = [c.strip() for c in feature_cols]
    for col_orig, col_stripped in zip(feature_cols, stripped_feat):
        if col_stripped in df_raw.columns:
            df_aligned[col_stripped] = pd.to_numeric(
                df_raw[col_stripped], errors="coerce"
            ).fillna(0.0)

    # Replace inf
    df_aligned = df_aligned.replace([np.inf, -np.inf], 0.0)

    X = scaler.transform(df_aligned.values.astype(np.float32))
    return X


# ─────────────────────────────────────────────────────────────────
# PREDICTION
# ─────────────────────────────────────────────────────────────────
def predict(df_raw, model, scaler, le, feature_cols, return_proba=True):
    """
    Full inference pipeline:
      raw DataFrame → preprocess → predict → decoded labels

    Returns DataFrame with columns: prediction, confidence, [class probabilities]
    """
    X = preprocess_for_inference(df_raw, feature_cols, scaler)

    y_pred_enc = model.predict(X)
    y_pred = le.inverse_transform(y_pred_enc)

    results = pd.DataFrame({"prediction": y_pred}, index=df_raw.index)

    if return_proba and hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)
        results["confidence"] = proba.max(axis=1).round(4)
        for i, cls in enumerate(le.classes_):
            results[f"prob_{cls}"] = proba[:, i].round(4)
    else:
        results["confidence"] = 1.0

    return results


# ─────────────────────────────────────────────────────────────────
# ZEEK conn.log → CICIDS2017 FEATURE TRANSLATION
# ─────────────────────────────────────────────────────────────────
def translate_zeek_conn_log(zeek_df):
    """
    Translate Zeek conn.log fields into CICIDS2017-compatible features.

    Zeek conn.log columns used:
        ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
        proto, service, duration, orig_bytes, resp_bytes,
        orig_pkts, resp_pkts, orig_ip_bytes, resp_ip_bytes,
        history

    Returns a DataFrame with CICIDS2017-style column names.
    """
    df = zeek_df.copy()

    # Rename columns
    out = pd.DataFrame()
    out["Destination Port"]         = pd.to_numeric(df.get("id.resp_p", 0), errors="coerce").fillna(0)
    out["Flow Duration"]            = pd.to_numeric(df.get("duration", 0), errors="coerce").fillna(0) * 1e6  # s → µs

    out["Total Fwd Packets"]        = pd.to_numeric(df.get("orig_pkts", 0), errors="coerce").fillna(0)
    out["Total Backward Packets"]   = pd.to_numeric(df.get("resp_pkts", 0), errors="coerce").fillna(0)
    out["Total Length of Fwd Packets"] = pd.to_numeric(df.get("orig_bytes", 0), errors="coerce").fillna(0)
    out["Total Length of Bwd Packets"] = pd.to_numeric(df.get("resp_bytes", 0), errors="coerce").fillna(0)

    # Derived rates (guard div-by-zero)
    dur_s = pd.to_numeric(df.get("duration", 0), errors="coerce").replace(0, np.nan)
    orig_bytes = pd.to_numeric(df.get("orig_bytes", 0), errors="coerce").fillna(0)
    resp_bytes = pd.to_numeric(df.get("resp_bytes", 0), errors="coerce").fillna(0)
    total_pkts = out["Total Fwd Packets"] + out["Total Backward Packets"]
    total_bytes = orig_bytes + resp_bytes

    out["Flow Bytes/s"]             = (total_bytes / dur_s).fillna(0)
    out["Flow Packets/s"]           = (total_pkts / dur_s).fillna(0)
    out["Fwd Packets/s"]            = (out["Total Fwd Packets"] / dur_s).fillna(0)
    out["Bwd Packets/s"]            = (out["Total Backward Packets"] / dur_s).fillna(0)

    # Avg segment sizes
    out["Avg Fwd Segment Size"]     = (orig_bytes / out["Total Fwd Packets"].replace(0, np.nan)).fillna(0)
    out["Avg Bwd Segment Size"]     = (resp_bytes / out["Total Backward Packets"].replace(0, np.nan)).fillna(0)
    out["Average Packet Size"]      = (total_bytes / total_pkts.replace(0, np.nan)).fillna(0)

    # Down/Up ratio
    out["Down/Up Ratio"]            = (out["Total Backward Packets"] / out["Total Fwd Packets"].replace(0, np.nan)).fillna(0)

    # TCP flags from Zeek 'history' field (S=SYN, F=FIN, R=RST, P=PSH, A=ACK)
    if "history" in df.columns:
        hist = df["history"].fillna("").astype(str)
        out["SYN Flag Count"]  = hist.str.count("S").astype(int)
        out["FIN Flag Count"]  = hist.str.count("F").astype(int)
        out["RST Flag Count"]  = hist.str.count("R").astype(int)
        out["PSH Flag Count"]  = hist.str.count("P").astype(int)
        out["ACK Flag Count"]  = hist.str.count("A").astype(int)
        out["URG Flag Count"]  = hist.str.count("U").astype(int)
    else:
        for flag in ["SYN Flag Count", "FIN Flag Count", "RST Flag Count",
                     "PSH Flag Count", "ACK Flag Count", "URG Flag Count"]:
            out[flag] = 0

    # Subflows (approximate from totals)
    out["Subflow Fwd Packets"] = out["Total Fwd Packets"]
    out["Subflow Fwd Bytes"]   = out["Total Length of Fwd Packets"]
    out["Subflow Bwd Packets"] = out["Total Backward Packets"]
    out["Subflow Bwd Bytes"]   = out["Total Length of Bwd Packets"]

    # Features not derivable from basic conn.log → set to 0
    # (IAT stats, packet-length stats, window sizes require custom Zeek scripts)
    for col in [
        "Fwd Packet Length Max", "Fwd Packet Length Min",
        "Fwd Packet Length Mean", "Bwd Packet Length Max",
        "Bwd Packet Length Mean", "Min Packet Length", "Max Packet Length",
        "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
        "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
        "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std",
        "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std",
        "Fwd Header Length", "Bwd Header Length",
        "Init_Win_bytes_forward", "Init_Win_bytes_backward",
        "Active Mean", "Active Std", "Idle Mean", "Idle Std",
    ]:
        out[col] = 0.0

    return out


# ─────────────────────────────────────────────────────────────────
# DEMO WITH SYNTHETIC DATA
# ─────────────────────────────────────────────────────────────────
def run_demo(model, scaler, le, feature_cols):
    """Run a demonstration with synthetic flow records."""
    print("\n" + "=" * 60)
    print("INFERENCE DEMO — Synthetic Flow Samples")
    print("=" * 60)

    # Create synthetic records mimicking different attack types
    rng = np.random.default_rng(99)
    stripped = [c.strip() for c in feature_cols]

    records = {
        "Normal_HTTP": {
            "Destination Port": 80, "Flow Duration": 500000,
            "Total Fwd Packets": 5, "Total Backward Packets": 4,
            "Total Length of Fwd Packets": 2000, "Total Length of Bwd Packets": 8000,
            "Flow Bytes/s": 20000, "Flow Packets/s": 18, "SYN Flag Count": 1,
            "FIN Flag Count": 1, "ACK Flag Count": 8, "RST Flag Count": 0,
        },
        "SYN_Flood_DDoS": {
            "Destination Port": 80, "Flow Duration": 50,
            "Total Fwd Packets": 1000, "Total Backward Packets": 0,
            "Total Length of Fwd Packets": 64000, "Total Length of Bwd Packets": 0,
            "Flow Bytes/s": 1280000, "Flow Packets/s": 20000, "SYN Flag Count": 1000,
            "FIN Flag Count": 0, "ACK Flag Count": 0, "RST Flag Count": 0,
        },
        "SSH_BruteForce": {
            "Destination Port": 22, "Flow Duration": 30000000,
            "Total Fwd Packets": 500, "Total Backward Packets": 500,
            "Total Length of Fwd Packets": 32000, "Total Length of Bwd Packets": 32000,
            "Flow Bytes/s": 2133, "Flow Packets/s": 33, "SYN Flag Count": 500,
            "FIN Flag Count": 500, "ACK Flag Count": 1000, "RST Flag Count": 50,
        },
        "PortScan": {
            "Destination Port": 0, "Flow Duration": 100,
            "Total Fwd Packets": 1, "Total Backward Packets": 0,
            "Total Length of Fwd Packets": 40, "Total Length of Bwd Packets": 0,
            "Flow Bytes/s": 400000, "Flow Packets/s": 10000, "SYN Flag Count": 1,
            "FIN Flag Count": 0, "ACK Flag Count": 0, "RST Flag Count": 0,
        },
    }

    df_demo = pd.DataFrame.from_dict(records, orient="index")
    results = predict(df_demo, model, scaler, le, feature_cols, return_proba=True)

    print(f"\n{'Sample':20s}  {'Prediction':15s}  {'Confidence':>12}")
    print("─" * 55)
    for idx in results.index:
        pred = results.loc[idx, "prediction"]
        conf = results.loc[idx, "confidence"]
        print(f"  {idx:20s}  {pred:15s}  {conf:12.4f}")

    print("\nFull probability breakdown:")
    prob_cols = [c for c in results.columns if c.startswith("prob_")]
    print(results[["prediction", "confidence"] + prob_cols].to_string())

    return results


# ─────────────────────────────────────────────────────────────────
# BATCH CSV PREDICTION
# ─────────────────────────────────────────────────────────────────
def predict_csv(input_path, output_path, model, scaler, le, feature_cols):
    """Load a CSV of flow features, predict, save results."""
    print(f"\n[BATCH] Loading: {input_path}")
    df = pd.read_csv(input_path, low_memory=False)
    print(f"  Rows: {len(df):,}  |  Columns: {len(df.columns)}")

    results = predict(df, model, scaler, le, feature_cols)
    out_df = pd.concat([df, results], axis=1)
    out_df.to_csv(output_path, index=False)
    print(f"[BATCH] Predictions saved: {output_path}")

    print("\n[BATCH] Attack summary:")
    print(results["prediction"].value_counts().to_string())
    return results


# ─────────────────────────────────────────────────────────────────
# ZEEK conn.log PREDICTION
# ─────────────────────────────────────────────────────────────────
def predict_zeek_log(zeek_path, model, scaler, le, feature_cols):
    """
    Parse a Zeek conn.log (TSV), translate features, predict.

    Zeek conn.log is tab-separated with a header line starting with '#fields'.
    """
    print(f"\n[ZEEK] Loading conn.log: {zeek_path}")
    # Zeek logs have comment lines starting with #
    with open(zeek_path) as f:
        lines = [l for l in f if not l.startswith("#separator") and
                 not l.startswith("#set_separator")]
    # Extract header
    header_line = None
    data_lines = []
    for line in lines:
        if line.startswith("#fields"):
            header_line = line.strip().replace("#fields\t", "").split("\t")
        elif not line.startswith("#"):
            data_lines.append(line)

    if header_line is None:
        print("[ZEEK] No #fields header found. Trying auto-parse...")
        df_zeek = pd.read_csv(zeek_path, sep="\t", comment="#")
    else:
        from io import StringIO
        data_str = "".join(data_lines)
        df_zeek = pd.read_csv(StringIO(data_str), sep="\t",
                               names=header_line, na_values=["-", "(empty)"])

    print(f"  Zeek records: {len(df_zeek):,}")
    df_translated = translate_zeek_conn_log(df_zeek)
    results = predict(df_translated, model, scaler, le, feature_cols)

    print("\n[ZEEK] Predicted attack distribution:")
    print(results["prediction"].value_counts().to_string())

    return results


# ─────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="IDS Inference Pipeline")
    parser.add_argument("--input", help="Path to input CSV with flow features")
    parser.add_argument("--output", help="Path to save predictions CSV",
                        default="predictions.csv")
    parser.add_argument("--zeek", help="Path to Zeek conn.log file")
    parser.add_argument("--demo", action="store_true",
                        help="Run demo with synthetic data")
    parser.add_argument("--model_dir", default=ARTIFACT_DIR,
                        help="Directory containing model artifacts")
    args = parser.parse_args()

    # Override artifact paths if custom dir
    model_path  = os.path.join(args.model_dir, "model.pkl")
    scaler_path = os.path.join(args.model_dir, "scaler.pkl")
    le_path     = os.path.join(args.model_dir, "label_encoder.pkl")
    feat_path   = os.path.join(args.model_dir, "feature_columns.json")

    model, scaler, le, feature_cols = load_artifacts(
        model_path, scaler_path, le_path, feat_path
    )

    if args.demo or (not args.input and not args.zeek):
        run_demo(model, scaler, le, feature_cols)

    if args.input:
        predict_csv(args.input, args.output, model, scaler, le, feature_cols)

    if args.zeek:
        predict_zeek_log(args.zeek, model, scaler, le, feature_cols)


if __name__ == "__main__":
    main()
