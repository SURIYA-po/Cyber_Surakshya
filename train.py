"""
train.py
========
End-to-end training pipeline for the CICIDS2017 multiclass IDS.
Trains Random Forest, Extra Trees, Gradient Boosting, and a Voting Ensemble.
Selects best model by weighted F1-score and saves all artifacts.

Usage:
    python train.py
"""

import os
import json
import time
import warnings
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import joblib

from sklearn.ensemble import (
    RandomForestClassifier,
    ExtraTreesClassifier,
    GradientBoostingClassifier,
    VotingClassifier,
)
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.preprocessing import label_binarize

warnings.filterwarnings("ignore")

# Import our preprocessing module
import sys
sys.path.insert(0, os.path.dirname(__file__))
from preprocess import run_preprocessing

# ─────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ARTIFACT_DIR = os.environ.get("ARTIFACT_DIR", os.path.join(BASE_DIR, "artifacts"))
PLOT_DIR = os.environ.get("PLOT_DIR", os.path.join(BASE_DIR, "plots"))
RANDOM_STATE = 42
TOP_K_FEATURES = 40
BALANCE_STRATEGY = "hybrid"

os.makedirs(ARTIFACT_DIR, exist_ok=True)
os.makedirs(PLOT_DIR, exist_ok=True)


# ─────────────────────────────────────────────────────────────────
# MODEL DEFINITIONS
# ─────────────────────────────────────────────────────────────────
def get_models():
    """Return dict of model name → estimator."""
    models = {
        "RandomForest": RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_leaf=2,
            class_weight="balanced",
            n_jobs=-1,
            random_state=RANDOM_STATE,
        ),
        "ExtraTrees": ExtraTreesClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_leaf=2,
            class_weight="balanced",
            n_jobs=-1,
            random_state=RANDOM_STATE,
        ),
        "GradientBoosting": GradientBoostingClassifier(
            n_estimators=150,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            random_state=RANDOM_STATE,
        ),
    }
    return models


# ─────────────────────────────────────────────────────────────────
# TRAINING
# ─────────────────────────────────────────────────────────────────
def train_models(X_train, y_train, models):
    """Train all models and track wall-clock time."""
    results = {}
    trained_models = {}

    for name, model in models.items():
        print(f"\n[TRAIN] Training {name}...")
        t0 = time.time()
        model.fit(X_train, y_train)
        elapsed = time.time() - t0
        print(f"  → Done in {elapsed:.1f}s")
        trained_models[name] = model
        results[name] = {"train_time_s": round(elapsed, 2)}

    return trained_models, results


# ─────────────────────────────────────────────────────────────────
# EVALUATION
# ─────────────────────────────────────────────────────────────────
def evaluate_model(model, X_test, y_test, class_names, model_name):
    """Compute full classification metrics for one model."""
    y_pred = model.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, average="weighted", zero_division=0)
    rec = recall_score(y_test, y_pred, average="weighted", zero_division=0)
    f1w = f1_score(y_test, y_pred, average="weighted", zero_division=0)

    report = classification_report(y_test, y_pred,
                                   target_names=class_names,
                                   zero_division=0)

    # ROC-AUC (one-vs-rest, if model has predict_proba)
    roc_auc = None
    if hasattr(model, "predict_proba"):
        try:
            y_prob = model.predict_proba(X_test)
            y_bin = label_binarize(y_test, classes=np.arange(len(class_names)))
            roc_auc = roc_auc_score(y_bin, y_prob, multi_class="ovr",
                                    average="weighted")
        except Exception:
            pass

    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)

    metrics = {
        "accuracy": round(acc, 4),
        "precision_weighted": round(prec, 4),
        "recall_weighted": round(rec, 4),
        "f1_weighted": round(f1w, 4),
        "roc_auc_ovr_weighted": round(roc_auc, 4) if roc_auc else "N/A",
    }

    print(f"\n[EVAL] {model_name}")
    print(f"  Accuracy         : {acc:.4f}")
    print(f"  Weighted F1      : {f1w:.4f}")
    print(f"  Weighted Precision: {prec:.4f}")
    print(f"  Weighted Recall  : {rec:.4f}")
    if roc_auc:
        print(f"  ROC-AUC (OvR)   : {roc_auc:.4f}")
    print("\n" + report)

    return metrics, report, cm, y_pred


# ─────────────────────────────────────────────────────────────────
# CONFUSION MATRIX PLOT
# ─────────────────────────────────────────────────────────────────
def save_confusion_matrix(cm, class_names, model_name, save_dir):
    """Save normalized confusion matrix as PNG."""
    cm_norm = cm.astype(float) / cm.sum(axis=1, keepdims=True)
    fig, ax = plt.subplots(figsize=(10, 8))
    disp = ConfusionMatrixDisplay(confusion_matrix=cm_norm,
                                  display_labels=class_names)
    disp.plot(ax=ax, cmap="Blues", colorbar=True, xticks_rotation=45)
    ax.set_title(f"Confusion Matrix (Normalized) — {model_name}", fontsize=13)
    plt.tight_layout()
    path = os.path.join(save_dir, f"confusion_matrix_{model_name}.png")
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"  [PLOT] Confusion matrix saved: {path}")
    return path


# ─────────────────────────────────────────────────────────────────
# FEATURE IMPORTANCE PLOT
# ─────────────────────────────────────────────────────────────────
def save_feature_importance(model, feature_names, model_name, save_dir, top_n=20):
    """Save top-N feature importance bar chart."""
    if not hasattr(model, "feature_importances_"):
        return None

    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1][:top_n]
    top_feats = [feature_names[i] for i in indices]
    top_vals = importances[indices]

    fig, ax = plt.subplots(figsize=(10, 7))
    colors = plt.cm.viridis(np.linspace(0.2, 0.9, top_n))
    bars = ax.barh(range(top_n), top_vals[::-1], color=colors[::-1])
    ax.set_yticks(range(top_n))
    ax.set_yticklabels([f[:35] for f in top_feats[::-1]], fontsize=9)
    ax.set_xlabel("Feature Importance (Gini)", fontsize=11)
    ax.set_title(f"Top {top_n} Feature Importances — {model_name}", fontsize=13)
    plt.tight_layout()
    path = os.path.join(save_dir, f"feature_importance_{model_name}.png")
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"  [PLOT] Feature importance saved: {path}")

    # Print top 10
    print(f"\n[IMPORTANCE] Top 10 features for {model_name}:")
    for i in range(min(10, top_n)):
        print(f"  {i+1:2d}. {top_feats[i]:40s}  {top_vals[i]:.4f}")

    return path


# ─────────────────────────────────────────────────────────────────
# EVALUATION REPORT
# ─────────────────────────────────────────────────────────────────
def save_evaluation_report(all_results, all_reports, class_names,
                            feature_cols, best_model_name, save_dir):
    """Write full evaluation report to text file."""
    from preprocess import ZEEK_FIELD_MAPPING

    lines = [
        "=" * 70,
        "   CICIDS2017 IDS — EVALUATION REPORT",
        "=" * 70,
        "",
        f"Number of classes   : {len(class_names)}",
        f"Classes             : {', '.join(class_names)}",
        f"Selected features   : {len(feature_cols)}",
        f"Best model          : {best_model_name}",
        "",
        "─" * 70,
        "METRICS SUMMARY",
        "─" * 70,
    ]

    for name, metrics in all_results.items():
        lines.append(f"\n  {name}")
        for k, v in metrics.items():
            lines.append(f"    {k:35s}: {v}")

    lines += [
        "",
        "─" * 70,
        "DETAILED CLASSIFICATION REPORTS",
        "─" * 70,
    ]
    for name, report in all_reports.items():
        lines.append(f"\n{'='*40} {name}\n")
        lines.append(report)

    lines += [
        "",
        "─" * 70,
        "SELECTED FEATURE COLUMNS",
        "─" * 70,
    ]
    for i, f in enumerate(feature_cols, 1):
        lines.append(f"  {i:2d}. {f}")

    lines += [
        "",
        "─" * 70,
        "ZEEK conn.log → CICIDS2017 FEATURE MAPPING",
        "─" * 70,
        ZEEK_FIELD_MAPPING,
    ]

    report_path = os.path.join(save_dir, "evaluation_report.txt")
    with open(report_path, "w") as f:
        f.write("\n".join(lines))
    print(f"\n[REPORT] Evaluation report saved: {report_path}")
    return report_path


# ─────────────────────────────────────────────────────────────────
# CLASS DISTRIBUTION PLOT
# ─────────────────────────────────────────────────────────────────
def plot_class_distribution(y_enc, le, save_dir):
    """Save class distribution bar chart."""
    from collections import Counter
    counts = Counter(le.inverse_transform(y_enc))
    labels = sorted(counts.keys())
    values = [counts[l] for l in labels]

    fig, ax = plt.subplots(figsize=(10, 5))
    colors = plt.cm.Set2(np.linspace(0, 1, len(labels)))
    ax.bar(labels, values, color=colors)
    ax.set_xlabel("Attack Class", fontsize=11)
    ax.set_ylabel("Sample Count", fontsize=11)
    ax.set_title("Class Distribution (Training Set)", fontsize=13)
    for i, v in enumerate(values):
        ax.text(i, v + max(values)*0.01, f"{v:,}", ha="center", fontsize=8)
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    path = os.path.join(save_dir, "class_distribution.png")
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"  [PLOT] Class distribution saved: {path}")
    return path


# ─────────────────────────────────────────────────────────────────
# MAIN TRAINING PIPELINE
# ─────────────────────────────────────────────────────────────────
def main():
    print("\n" + "=" * 70)
    print("  CICIDS2017 IDS — FULL TRAINING PIPELINE")
    print("  Research: Real-Time AI-Based IDS using CICIDS2017 + Zeek")
    print("=" * 70)

    # ── PREPROCESSING ────────────────────────────────────────────
    (X_train, X_test, y_train, y_test,
     scaler, le, feature_cols, _) = run_preprocessing(
        top_k=TOP_K_FEATURES,
        balance_strategy=BALANCE_STRATEGY,
        output_dir=ARTIFACT_DIR,
    )

    class_names = list(le.classes_)
    n_classes = len(class_names)

    # ── CLASS DISTRIBUTION PLOT ──────────────────────────────────
    plot_class_distribution(y_train, le, PLOT_DIR)

    # ── TRAIN MODELS ─────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("TRAINING MODELS")
    print("=" * 70)
    models_dict = get_models()
    trained_models, train_results = train_models(X_train, y_train, models_dict)

    # ── EVALUATE MODELS ──────────────────────────────────────────
    print("\n" + "=" * 70)
    print("EVALUATING MODELS")
    print("=" * 70)
    all_metrics = {}
    all_reports = {}
    all_cms = {}

    for name, model in trained_models.items():
        metrics, report, cm, _ = evaluate_model(
            model, X_test, y_test, class_names, name
        )
        metrics.update(train_results[name])
        all_metrics[name] = metrics
        all_reports[name] = report
        all_cms[name] = cm

        save_confusion_matrix(cm, class_names, name, PLOT_DIR)
        save_feature_importance(model, feature_cols, name, PLOT_DIR)

    # ── BUILD VOTING ENSEMBLE (RF + ET) ──────────────────────────
    print("\n[ENSEMBLE] Building Voting Ensemble (RF + ET)...")
    voting_clf = VotingClassifier(
        estimators=[
            ("rf", trained_models["RandomForest"]),
            ("et", trained_models["ExtraTrees"]),
        ],
        voting="soft",
        n_jobs=-1,
    )
    # Note: VotingClassifier with pre-fitted estimators needs re-fit
    voting_clf.fit(X_train, y_train)
    v_metrics, v_report, v_cm, _ = evaluate_model(
        voting_clf, X_test, y_test, class_names, "VotingEnsemble"
    )
    v_metrics["train_time_s"] = "N/A"
    all_metrics["VotingEnsemble"] = v_metrics
    all_reports["VotingEnsemble"] = v_report
    all_cms["VotingEnsemble"] = v_cm
    trained_models["VotingEnsemble"] = voting_clf
    save_confusion_matrix(v_cm, class_names, "VotingEnsemble", PLOT_DIR)

    # ── SELECT BEST MODEL ────────────────────────────────────────
    print("\n" + "=" * 70)
    print("MODEL COMPARISON")
    print("=" * 70)
    print(f"{'Model':20s}  {'Accuracy':>10}  {'F1 (wt)':>10}  {'Recall':>10}  {'Precision':>10}")
    print("─" * 65)

    best_name = None
    best_f1 = -1
    for name, m in all_metrics.items():
        f1 = m["f1_weighted"]
        acc = m["accuracy"]
        rec = m["recall_weighted"]
        prec = m["precision_weighted"]
        print(f"  {name:20s}  {acc:>10.4f}  {f1:>10.4f}  {rec:>10.4f}  {prec:>10.4f}")
        if f1 > best_f1:
            best_f1 = f1
            best_name = name

    print(f"\n★  Best model: {best_name}  (Weighted F1 = {best_f1:.4f})")

    # ── SAVE BEST MODEL ──────────────────────────────────────────
    best_model = trained_models[best_name]
    model_path = os.path.join(ARTIFACT_DIR, "model.pkl")
    joblib.dump(best_model, model_path)
    print(f"[SAVE] Best model saved: {model_path}")

    # Also save all models
    for name, model in trained_models.items():
        p = os.path.join(ARTIFACT_DIR, f"model_{name}.pkl")
        joblib.dump(model, p)

    # ── EVALUATION REPORT ────────────────────────────────────────
    save_evaluation_report(
        all_metrics, all_reports, class_names,
        feature_cols, best_name,
        ARTIFACT_DIR,
    )

    # ── FINAL SUMMARY ────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("TRAINING COMPLETE — ARTIFACTS SAVED")
    print("=" * 70)
    print(f"  Model      : {ARTIFACT_DIR}/model.pkl")
    print(f"  Scaler     : {ARTIFACT_DIR}/scaler.pkl")
    print(f"  LabelEncoder: {ARTIFACT_DIR}/label_encoder.pkl")
    print(f"  Features   : {ARTIFACT_DIR}/feature_columns.json")
    print(f"  Report     : {ARTIFACT_DIR}/evaluation_report.txt")
    print(f"  Plots      : {PLOT_DIR}/")
    print("\n[Zeek Integration Note]")
    print("  The selected features map closely to Zeek conn.log fields.")
    print("  See evaluation_report.txt for the full mapping table.")
    print("  Use inference.py to run predictions on new flow data.")

    return best_model, scaler, le, feature_cols


if __name__ == "__main__":
    main()
