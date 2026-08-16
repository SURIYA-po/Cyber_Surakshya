"""
train.py
========
NEW PIPELINE — trains the CICIDS2017 IDS on four model families:

  1. Random Forest      (RF)
  2. Gradient Boosting  (GB) — uses HistGradientBoosting for speed
  3. Deep Neural Net    (DNN) — sklearn MLPClassifier
  4. Voting Ensemble    (RF + GB + DNN, soft vote)

Additionally trains an Anomaly Detection layer:
  5. Autoencoder (for known-pattern reconstruction error)
  6. Isolation Forest   (for pattern-based novelty detection)

The anomaly layer fires at inference time when a new/unseen pattern is detected,
even if the supervised classifier outputs BENIGN.  This is the "reactive second
opinion" layer described in the research paper.

Research ref:
  "Deep Learning-Based Intrusion Detection in Computer Systems and Networks:
   Advances, Hybrids, and Challenges 2022–2026"  — KhPI AIS Journal 2025

Usage
-----
    python train.py                        # full pipeline, all defaults
    python train.py --max_rows 200000      # lighter run for quick test
    python train.py --no_dnn               # skip DNN (fastest)
    python train.py --artifact_dir /my/dir # custom save location
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import warnings
from datetime import datetime, timezone

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from sklearn.ensemble import (
    HistGradientBoostingClassifier,
    IsolationForest,
    RandomForestClassifier,
    VotingClassifier,
)
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import label_binarize

warnings.filterwarnings("ignore")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from preprocess import run_preprocessing

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION DEFAULTS
# ─────────────────────────────────────────────────────────────────────────────

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
ARTIFACT_DIR = os.environ.get("ARTIFACT_DIR", os.path.join(BASE_DIR, "artifacts"))
PLOT_DIR     = os.environ.get("PLOT_DIR",     os.path.join(BASE_DIR, "figures"))
RANDOM_STATE = 42
TOP_K        = 40

os.makedirs(ARTIFACT_DIR, exist_ok=True)
os.makedirs(PLOT_DIR,     exist_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# MODEL DEFINITIONS
# ─────────────────────────────────────────────────────────────────────────────

def get_supervised_models(include_dnn: bool = True) -> dict:
    """
    Return dict of model_name → (unfitted) estimator.

    Hyperparameters are tuned for balanced performance on CICIDS2017:
    - RF: 300 trees, max_depth=None (full depth); class_weight balanced
    - GB: HistGradientBoosting (100× faster than GradientBoostingClassifier)
    - DNN: 3-layer MLP with ReLU; early stopping; Adam optimiser
    """
    models: dict = {
        # ── Random Forest ────────────────────────────────────────────────────
        "RandomForest": RandomForestClassifier(
            n_estimators=300,
            max_depth=None,            # grow full trees; RF regularises via bagging
            min_samples_leaf=1,
            max_features="sqrt",
            class_weight="balanced",
            n_jobs=-1,
            random_state=RANDOM_STATE,
            verbose=0,
        ),

        # ── Histogram Gradient Boosting (scikit-learn's fast GB) ─────────────
        # Equivalent to LightGBM-style boosting; handles large datasets well.
        # Research paper uses Gradient Boosting; HistGB achieves same accuracy
        # with ~10× speedup on 500 k rows.
        "GradientBoosting": HistGradientBoostingClassifier(
            max_iter=300,
            max_depth=8,
            learning_rate=0.05,
            min_samples_leaf=20,
            l2_regularization=1.0,
            max_bins=255,
            class_weight="balanced",
            early_stopping=True,
            validation_fraction=0.1,
            n_iter_no_change=20,
            random_state=RANDOM_STATE,
            verbose=0,
        ),
    }

    if include_dnn:
        # ── Deep Neural Network (MLP) ────────────────────────────────────────
        # 3 hidden layers; batch normalisation is not available in sklearn MLP
        # but we apply StandardScaler upstream.  Dropout is approximated via
        # alpha (L2 regularisation).
        models["DNN"] = MLPClassifier(
            hidden_layer_sizes=(512, 256, 128),
            activation="relu",
            solver="adam",
            alpha=1e-4,                # L2 regularisation
            batch_size=256,
            learning_rate="adaptive",
            learning_rate_init=1e-3,
            max_iter=100,
            early_stopping=True,
            validation_fraction=0.10,
            n_iter_no_change=10,
            random_state=RANDOM_STATE,
            verbose=False,
        )

    return models


# ─────────────────────────────────────────────────────────────────────────────
# TRAINING
# ─────────────────────────────────────────────────────────────────────────────

def train_supervised(
    X_train: np.ndarray,
    y_train: np.ndarray,
    models:  dict,
) -> tuple[dict, dict]:
    """Fit all supervised models; return (trained_models, timing_results)."""
    trained: dict = {}
    timing:  dict = {}

    for name, model in models.items():
        print(f"\n[TRAIN] ── {name} ──────────────────────────────")
        t0 = time.time()
        model.fit(X_train, y_train)
        elapsed = time.time() - t0
        print(f"  ✓ Done in {elapsed:.1f}s")
        trained[name] = model
        timing[name]  = {"train_time_s": round(elapsed, 2)}

    return trained, timing


# ─────────────────────────────────────────────────────────────────────────────
# VOTING ENSEMBLE
# ─────────────────────────────────────────────────────────────────────────────

def build_voting_ensemble(
    trained_models: dict,
    X_train: np.ndarray,
    y_train: np.ndarray,
) -> VotingClassifier:
    """
    Build a soft-voting ensemble from all trained supervised classifiers.

    All base estimators support predict_proba, so soft voting is used.
    """
    estimators = [(name, model) for name, model in trained_models.items()]

    print(f"\n[ENSEMBLE] Building Voting Ensemble from: "
          f"{[n for n, _ in estimators]}")

    voting_clf = VotingClassifier(
        estimators=estimators,
        voting="soft",
        n_jobs=-1,
    )
    t0 = time.time()
    voting_clf.fit(X_train, y_train)
    print(f"  ✓ Ensemble fitted in {time.time() - t0:.1f}s")
    return voting_clf


# ─────────────────────────────────────────────────────────────────────────────
# ANOMALY DETECTION LAYER
# ─────────────────────────────────────────────────────────────────────────────

def train_anomaly_layer(
    X_benign: np.ndarray,
    X_all_train: np.ndarray,
    contamination: float = 0.05,
    random_state:  int   = RANDOM_STATE,
) -> dict:
    """
    Train two complementary anomaly detectors on BENIGN traffic only.

    1. Isolation Forest   — detects statistical outliers (global anomaly)
    2. Autoencoder        — detects reconstruction deviation (local pattern)

    Both are trained exclusively on BENIGN samples so they learn "normal"
    behaviour.  At inference time, any sample that scores above the threshold
    on EITHER detector triggers the anomaly flag, regardless of what the
    supervised classifier predicts.

    Parameters
    ----------
    X_benign     : scaled BENIGN-only training samples
    X_all_train  : all training samples (used to calibrate thresholds)
    contamination: expected fraction of anomalies in X_all_train for IF

    Returns
    -------
    dict with keys: 'iforest', 'autoencoder', 'ae_threshold', 'if_threshold'
    """
    artifacts: dict = {}

    # ── Isolation Forest ─────────────────────────────────────────────────────
    print("\n[ANOMALY] Training Isolation Forest on BENIGN samples…")
    t0 = time.time()
    iforest = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        max_samples="auto",
        max_features=1.0,
        bootstrap=False,
        n_jobs=-1,
        random_state=random_state,
    )
    iforest.fit(X_benign)
    print(f"  ✓ IsolationForest fitted in {time.time() - t0:.1f}s")

    # Calibrate IF threshold: score at 95th percentile on BENIGN
    benign_scores = iforest.score_samples(X_benign)
    if_threshold  = float(np.percentile(benign_scores, 5))  # 5th %ile = boundary
    print(f"  IF anomaly threshold (5th %ile of benign scores): {if_threshold:.4f}")

    artifacts["iforest"]      = iforest
    artifacts["if_threshold"] = if_threshold

    # ── Autoencoder (numpy-based, no TF/PyTorch dependency) ──────────────────
    # Implemented as a shallow tied-weights autoencoder using gradient descent.
    # This avoids adding TensorFlow/PyTorch to requirements.
    # For a production system, replace with a Keras/PyTorch autoencoder.
    print("\n[ANOMALY] Training Autoencoder on BENIGN samples…")
    autoencoder = NumpyAutoencoder(
        input_dim=X_benign.shape[1],
        encoding_dim=max(8, X_benign.shape[1] // 4),
        learning_rate=1e-3,
        n_epochs=50,
        batch_size=256,
        random_state=random_state,
    )
    t0 = time.time()
    autoencoder.fit(X_benign)
    print(f"  ✓ Autoencoder fitted in {time.time() - t0:.1f}s")

    # Calibrate AE threshold: 99th percentile of BENIGN reconstruction error
    benign_errors = autoencoder.reconstruction_error(X_benign)
    ae_threshold  = float(np.percentile(benign_errors, 99))
    print(f"  AE anomaly threshold (99th %ile of benign recon error): {ae_threshold:.6f}")

    artifacts["autoencoder"]   = autoencoder
    artifacts["ae_threshold"]  = ae_threshold

    return artifacts


class NumpyAutoencoder:
    """
    Lightweight 3-layer autoencoder (encode → bottleneck → decode)
    implemented with pure NumPy / manual backprop.

    Architecture: input_dim → encoding_dim*2 → encoding_dim → encoding_dim*2 → input_dim
    Activation  : ReLU (hidden), Linear (output)
    Loss        : Mean Squared Error
    Optimiser   : Mini-batch SGD with momentum (no Adam to keep it simple)

    This is intentionally minimal — replace with Keras Autoencoder for
    production-grade use.
    """

    def __init__(
        self,
        input_dim:    int,
        encoding_dim: int   = 16,
        learning_rate: float = 1e-3,
        n_epochs:     int   = 50,
        batch_size:   int   = 256,
        random_state: int   = 42,
    ):
        self.input_dim    = input_dim
        self.enc_dim      = encoding_dim
        self.lr           = learning_rate
        self.n_epochs     = n_epochs
        self.batch_size   = batch_size
        self.rng          = np.random.default_rng(random_state)
        self._init_weights()

    def _init_weights(self):
        """Xavier initialisation."""
        d, e = self.input_dim, self.enc_dim
        h = e * 2   # hidden size

        def _xavier(fan_in, fan_out):
            scale = np.sqrt(2.0 / (fan_in + fan_out))
            return self.rng.normal(0, scale, (fan_in, fan_out)).astype(np.float32)

        self.W1 = _xavier(d, h);  self.b1 = np.zeros((1, h),  dtype=np.float32)
        self.W2 = _xavier(h, e);  self.b2 = np.zeros((1, e),  dtype=np.float32)
        self.W3 = _xavier(e, h);  self.b3 = np.zeros((1, h),  dtype=np.float32)
        self.W4 = _xavier(h, d);  self.b4 = np.zeros((1, d),  dtype=np.float32)

    @staticmethod
    def _relu(x):
        return np.maximum(0, x)

    @staticmethod
    def _relu_grad(x):
        return (x > 0).astype(np.float32)

    def _forward(self, X):
        h1 = self._relu(X  @ self.W1 + self.b1)
        h2 = self._relu(h1 @ self.W2 + self.b2)
        h3 = self._relu(h2 @ self.W3 + self.b3)
        out = h3 @ self.W4 + self.b4   # linear output
        return h1, h2, h3, out

    def fit(self, X: np.ndarray) -> NumpyAutoencoder:
        X = X.astype(np.float32)
        n = len(X)
        lr = self.lr

        for epoch in range(self.n_epochs):
            idx   = self.rng.permutation(n)
            epoch_loss = 0.0
            n_batches  = 0

            for start in range(0, n, self.batch_size):
                Xb = X[idx[start:start + self.batch_size]]
                h1, h2, h3, out = self._forward(Xb)

                # MSE loss
                diff       = out - Xb
                batch_loss = np.mean(diff ** 2)
                epoch_loss += batch_loss
                n_batches  += 1

                # Backprop
                dout = 2 * diff / len(Xb)

                dW4 = h3.T @ dout;  db4 = dout.sum(axis=0, keepdims=True)
                dh3 = dout @ self.W4.T * self._relu_grad(h3)

                dW3 = h2.T @ dh3;   db3 = dh3.sum(axis=0, keepdims=True)
                dh2 = dh3 @ self.W3.T * self._relu_grad(h2)

                dW2 = h1.T @ dh2;   db2 = dh2.sum(axis=0, keepdims=True)
                dh1 = dh2 @ self.W2.T * self._relu_grad(h1)

                dW1 = Xb.T @ dh1;   db1 = dh1.sum(axis=0, keepdims=True)

                # SGD update
                for W, dW, b, db in [
                    (self.W1, dW1, self.b1, db1),
                    (self.W2, dW2, self.b2, db2),
                    (self.W3, dW3, self.b3, db3),
                    (self.W4, dW4, self.b4, db4),
                ]:
                    W -= lr * np.clip(dW, -5.0, 5.0)
                    b -= lr * np.clip(db, -5.0, 5.0)

            if (epoch + 1) % 10 == 0 or epoch == 0:
                avg_loss = epoch_loss / max(n_batches, 1)
                print(f"    Epoch {epoch+1:3d}/{self.n_epochs}  MSE={avg_loss:.6f}")

        return self

    def reconstruction_error(self, X: np.ndarray) -> np.ndarray:
        """Return per-sample mean squared reconstruction error."""
        X    = X.astype(np.float32)
        _, _, _, out = self._forward(X)
        return np.mean((out - X) ** 2, axis=1)

    def is_anomaly(self, X: np.ndarray, threshold: float) -> np.ndarray:
        """Return boolean array: True if reconstruction error > threshold."""
        return self.reconstruction_error(X) > threshold


# ─────────────────────────────────────────────────────────────────────────────
# EVALUATION
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_model(
    model,
    X_test:     np.ndarray,
    y_test:     np.ndarray,
    class_names: list,
    model_name:  str,
) -> tuple:
    """Full classification metrics for one model."""
    y_pred = model.predict(X_test)

    acc   = accuracy_score(y_test, y_pred)
    prec  = precision_score(y_test, y_pred, average="weighted", zero_division=0)
    rec   = recall_score   (y_test, y_pred, average="weighted", zero_division=0)
    f1w   = f1_score       (y_test, y_pred, average="weighted", zero_division=0)
    # Macro averages weight every class equally, so a class the model almost
    # never catches cannot be hidden by the volume of the easy ones. On this
    # dataset weighted F1 reads 0.99 while macro F1 reads 0.84, because
    # WEBATTACK and BOTNET are both rare and poorly detected. Reporting only
    # the weighted figure overstates the model considerably.
    f1m   = f1_score       (y_test, y_pred, average="macro", zero_division=0)
    precm = precision_score(y_test, y_pred, average="macro", zero_division=0)
    recm  = recall_score   (y_test, y_pred, average="macro", zero_division=0)
    # Per-class recall, so the weakest class is a number the selector can act
    # on rather than something a human has to notice in the printed report.
    per_class_rec = recall_score(y_test, y_pred, average=None, zero_division=0)
    report = classification_report(y_test, y_pred,
                                   target_names=class_names,
                                   zero_division=0)

    roc_auc = None
    if hasattr(model, "predict_proba"):
        try:
            y_prob  = model.predict_proba(X_test)
            y_bin   = label_binarize(y_test, classes=np.arange(len(class_names)))
            roc_auc = roc_auc_score(y_bin, y_prob,
                                    multi_class="ovr", average="weighted")
        except Exception:
            pass

    cm = confusion_matrix(y_test, y_pred)

    metrics = {
        "accuracy":           round(float(acc),  4),
        "precision_weighted": round(float(prec), 4),
        "recall_weighted":    round(float(rec),  4),
        "f1_weighted":        round(float(f1w),  4),
        "f1_macro":           round(float(f1m),  4),
        "precision_macro":    round(float(precm), 4),
        "recall_macro":       round(float(recm), 4),
        "roc_auc_ovr_weighted": round(float(roc_auc), 4) if roc_auc is not None else "N/A",
        "per_class_recall": {
            cls: round(float(r), 4) for cls, r in zip(class_names, per_class_rec)
        },
        "min_class_recall": round(float(per_class_rec.min()), 4),
        "worst_class": class_names[int(per_class_rec.argmin())],
    }

    print(f"\n[EVAL] -- {model_name}")
    print(f"  Accuracy           : {acc:.4f}")
    print(f"  Weighted F1        : {f1w:.4f}")
    print(f"  MACRO F1           : {f1m:.4f}   <- per-class average; the honest headline")
    print(f"  Macro Recall       : {recm:.4f}")
    print(f"  Weighted Precision : {prec:.4f}")
    print(f"  Weighted Recall    : {rec:.4f}")
    if roc_auc is not None:
        print(f"  ROC-AUC (OvR)      : {roc_auc:.4f}")
    print("\n" + report)

    return metrics, report, cm


# ─────────────────────────────────────────────────────────────────────────────
# PLOTS
# ─────────────────────────────────────────────────────────────────────────────

def _save_confusion_matrix(cm, class_names, model_name, save_dir):
    cm_norm = cm.astype(float) / cm.sum(axis=1, keepdims=True)
    fig, ax = plt.subplots(figsize=(10, 8))
    disp = ConfusionMatrixDisplay(confusion_matrix=cm_norm,
                                  display_labels=class_names)
    disp.plot(ax=ax, cmap="Blues", colorbar=True, xticks_rotation=45)
    ax.set_title(f"Confusion Matrix (Normalised) — {model_name}", fontsize=13)
    plt.tight_layout()
    path = os.path.join(save_dir, f"cm_{model_name}.png")
    plt.savefig(path, dpi=150);  plt.close()
    print(f"  [PLOT] {path}")


def _save_feature_importance(model, feature_names, model_name, save_dir, top_n=20):
    if not hasattr(model, "feature_importances_"):
        return
    importances = model.feature_importances_
    idx    = np.argsort(importances)[::-1][:top_n]
    feats  = [feature_names[i] for i in idx]
    vals   = importances[idx]

    fig, ax = plt.subplots(figsize=(10, 7))
    colors  = plt.cm.viridis(np.linspace(0.2, 0.9, top_n))
    ax.barh(range(top_n), vals[::-1], color=colors[::-1])
    ax.set_yticks(range(top_n))
    ax.set_yticklabels([f[:35] for f in feats[::-1]], fontsize=9)
    ax.set_xlabel("Feature Importance", fontsize=11)
    ax.set_title(f"Top {top_n} Feature Importances — {model_name}", fontsize=13)
    plt.tight_layout()
    path = os.path.join(save_dir, f"fi_{model_name}.png")
    plt.savefig(path, dpi=150);  plt.close()
    print(f"  [PLOT] {path}")


def _save_class_distribution(y_enc, le, save_dir):
    from collections import Counter
    counts = Counter(le.inverse_transform(y_enc))
    labels = sorted(counts)
    values = [counts[label] for label in labels]
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(labels, values, color=plt.cm.Set2(np.linspace(0, 1, len(labels))))
    ax.set_xlabel("Class",     fontsize=11)
    ax.set_ylabel("# Samples", fontsize=11)
    ax.set_title("Balanced Training Class Distribution", fontsize=13)
    for i, v in enumerate(values):
        ax.text(i, v + max(values) * 0.01, f"{v:,}", ha="center", fontsize=8)
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    path = os.path.join(save_dir, "class_distribution.png")
    plt.savefig(path, dpi=150);  plt.close()
    print(f"  [PLOT] {path}")


def _plot_training_history(model_name, save_dir):
    """Plot loss curve for DNN (MLPClassifier exposes loss_curve_)."""
    pass  # Placeholder — MLPClassifier stores loss_curve_ automatically


# ─────────────────────────────────────────────────────────────────────────────
# REPORT
# ─────────────────────────────────────────────────────────────────────────────

# A model that catches fewer than this fraction of any single class is not
# fit to serve, whatever its headline score. Calibrated from the observed
# failure: RandomForest, GradientBoosting and VotingEnsemble all score >0.99
# weighted F1 while catching 8-10% of WEBATTACK. Selecting on weighted F1
# would happily promote one of them.
MIN_CLASS_RECALL = 0.50


def select_best_model(all_metrics: dict) -> str:
    """Choose the model to serve. Macro F1, with a per-class recall floor.

    Selection used to be `max(..., key=f1_weighted)`. Weighted metrics are
    dominated by the four high-volume classes (~99% of rows), so they cannot
    distinguish a model that detects every attack family from one that is
    blind to the two rarest. That is not a hypothetical: three of the four
    models trained here have <=0.10 recall on WEBATTACK and >0.99 weighted F1.

    Models clearing the floor are ranked by macro F1. If none clear it, the
    best macro F1 still wins -- refusing to save any model would leave the
    platform with no detector at all -- but the choice is reported loudly.
    """
    viable = {
        name: m for name, m in all_metrics.items()
        if m.get("min_class_recall", 0.0) >= MIN_CLASS_RECALL
    }
    if not viable:
        print(
            f"\n  [WARN] No model reaches {MIN_CLASS_RECALL:.0%} recall on every "
            "class. Selecting on macro F1 alone; the served model is blind to "
            "at least one attack family. Retrain with class weighting or "
            "targeted oversampling before relying on this."
        )
        viable = all_metrics

    rejected = set(all_metrics) - set(viable)
    if rejected:
        print(
            f"\n  Excluded for low per-class recall (<{MIN_CLASS_RECALL:.0%}): "
            + ", ".join(
                f"{n} ({all_metrics[n]['worst_class']}="
                f"{all_metrics[n]['min_class_recall']:.2f})"
                for n in sorted(rejected)
            )
        )

    return max(viable, key=lambda n: viable[n]["f1_macro"])


def _dataset_fingerprint(path: str) -> dict:
    """Identify the training data without hashing 717 MB.

    Size plus mtime plus a hash of the header and first rows is enough to tell
    "same file" from "different file", which is all the manifest needs.
    """
    import hashlib

    if not os.path.exists(path):
        return {"path": path, "available": False}

    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        digest.update(fh.read(1_000_000))
    stat = os.stat(path)
    return {
        "path":            os.path.basename(path),
        "available":       True,
        "size_bytes":      stat.st_size,
        "modified_utc":    datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        "head_sha256":     digest.hexdigest(),
        "_note":           "head_sha256 covers the first 1 MB only.",
    }


def write_manifest(
    *,
    save_dir: str,
    best_model_name: str,
    all_metrics: dict,
    class_names: list,
    feature_cols: list,
    dataset_path: str,
    config: dict,
    anomaly_enabled: bool,
) -> str:
    """Record which model is served and what produced it.

    Two problems this solves.

    WHICH MODEL IS SERVED. `inference.resolve_model_path` picked the first
    existing file from a hardcoded preference list, so the served model was
    decided by list order and whichever files happened to be on disk. Reading
    `served_model` here makes it an explicit, auditable choice.

    REPRODUCIBILITY. Nothing recorded the dataset, sample cap, seed, feature
    count, or library versions behind the committed artifacts, so they could
    not be regenerated or even identified.
    """
    import platform as _platform

    import sklearn

    manifest = {
        "schema_version": 1,
        "generated_utc":  datetime.now(timezone.utc).isoformat(),

        # The contract inference.py reads.
        "served_model":   f"model_{best_model_name}.pkl",
        "served_model_name": best_model_name,
        "selection_rule": (
            f"highest macro F1 among models with per-class recall "
            f">= {MIN_CLASS_RECALL:.0%}"
        ),

        "classes":        list(class_names),
        "feature_count":  len(feature_cols),
        "anomaly_layer":  anomaly_enabled,

        "metrics": {
            name: {
                k: v for k, v in m.items()
                if k in (
                    "accuracy", "f1_weighted", "f1_macro", "recall_macro",
                    "min_class_recall", "worst_class", "per_class_recall",
                )
            }
            for name, m in all_metrics.items()
        },

        "reproducibility": {
            "dataset":       _dataset_fingerprint(dataset_path),
            "config":        config,
            "random_state":  RANDOM_STATE,
            "python":        _platform.python_version(),
            "scikit_learn":  sklearn.__version__,
            "numpy":         np.__version__,
            "joblib":        joblib.__version__,
            "_note": (
                "joblib.load requires a scikit-learn compatible with the "
                "version above. A major mismatch can fail to unpickle the "
                "estimator classes."
            ),
        },
    }

    path = os.path.join(save_dir, "manifest.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    print(f"[SAVE] Manifest -> {path}")
    return path


def _save_report(all_metrics, all_reports, class_names, feature_cols,
                 best_model_name, save_dir):
    lines = [
        "=" * 70,
        "   CICIDS2017 IDS -- EVALUATION REPORT",
        "   Research: Real-Time AI-Based IDS (CICIDS2017 + Zeek/CICFlowMeter)",
        "=" * 70,
        f"\nClasses         : {', '.join(class_names)}",
        f"Selected features: {len(feature_cols)}",
        f"Best model       : {best_model_name}",
        "\n" + "-" * 70,
        "METRICS SUMMARY",
        "-" * 70,
        "",
        "  READ F1(macro) FIRST. Weighted metrics are dominated by the four",
        "  high-volume classes (BENIGN, DDOS, DOS, PORTSCAN) and hide poor",
        "  per-class recall on the rare ones. A model can read 0.99 weighted",
        "  and still miss most WEBATTACK and BOTNET flows.",
        "",
    ]
    hdr = (
        f"  {'Model':<22s}  {'Accuracy':>10}  {'F1(wt)':>8}  {'F1(macro)':>10}  "
        f"{'Rec(macro)':>11}  {'ROC-AUC':>8}"
    )
    lines.append(hdr)
    lines.append("  " + "-" * 74)
    for name, m in all_metrics.items():
        lines.append(
            f"  {name:<22s}  {m['accuracy']:>10.4f}  "
            f"{m['f1_weighted']:>8.4f}  {m.get('f1_macro', float('nan')):>10.4f}  "
            f"{m.get('recall_macro', float('nan')):>11.4f}  "
            f"{str(m['roc_auc_ovr_weighted']):>8}"
        )

    # Name every class whose recall falls below this, so a weak class is
    # stated in the report rather than left for a reader to derive.
    lines += [
        "",
        "  Weighted precision/recall are still available per model in the",
        "  detailed classification reports below.",
    ]

    lines += ["", "-" * 70, "DETAILED CLASSIFICATION REPORTS", "-" * 70]
    for name, rpt in all_reports.items():
        lines += [f"\n{'='*35} {name}", rpt]

    lines += ["", "-" * 70, "SELECTED FEATURES", "-" * 70]
    for i, f in enumerate(feature_cols, 1):
        lines.append(f"  {i:2d}. {f}")

    rpt_path = os.path.join(save_dir, "evaluation_report.txt")
    with open(rpt_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    print(f"\n[REPORT] Saved -> {rpt_path}")


# -----------------------------------------------------------------------------
# MAIN TRAINING PIPELINE
# -----------------------------------------------------------------------------

def main(args=None):
    parser = argparse.ArgumentParser(description="CICIDS2017 IDS Training Pipeline")
    parser.add_argument("--max_rows",    type=int,   default=500_000,
                        help="Max rows to sample from dataset (0=all)")
    parser.add_argument("--top_k",       type=int,   default=TOP_K,
                        help="Number of features to select")
    parser.add_argument("--no_dnn",      action="store_true",
                        help="Skip DNN training (faster for quick tests)")
    parser.add_argument("--no_anomaly",  action="store_true",
                        help="Skip anomaly layer training")
    parser.add_argument("--artifact_dir", default=ARTIFACT_DIR,
                        help="Directory to save model artifacts")
    parser.add_argument("--plot_dir",     default=PLOT_DIR,
                        help="Directory to save plots")
    cfg = parser.parse_args(args)

    os.makedirs(cfg.artifact_dir, exist_ok=True)
    os.makedirs(cfg.plot_dir,     exist_ok=True)

    print("\n" + "=" * 70)
    print("  CICIDS2017 IDS — FULL TRAINING PIPELINE")
    print("  Research: AI-Based IDS with Anomaly Detection Layer")
    print("=" * 70)

    # ── PREPROCESSING ────────────────────────────────────────────────────────
    (X_train, X_test, y_train, y_test,
     scaler, le, feature_cols) = run_preprocessing(
        max_rows=cfg.max_rows,
        top_k=cfg.top_k,
        output_dir=cfg.artifact_dir,
        balance_strategy="hybrid",
    )

    class_names  = list(le.classes_)
    benign_label = le.transform(["BENIGN"])[0]

    # ── CLASS DISTRIBUTION PLOT ──────────────────────────────────────────────
    _save_class_distribution(y_train, le, cfg.plot_dir)

    # ── SUPERVISED MODELS ────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("TRAINING SUPERVISED MODELS")
    print("=" * 70)

    models_dict   = get_supervised_models(include_dnn=not cfg.no_dnn)
    trained_models, timing = train_supervised(X_train, y_train, models_dict)

    # ── EVALUATE EACH MODEL ──────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("EVALUATING MODELS")
    print("=" * 70)

    all_metrics: dict = {}
    all_reports: dict = {}

    for name, model in trained_models.items():
        metrics, report, cm = evaluate_model(model, X_test, y_test,
                                             class_names, name)
        metrics.update(timing.get(name, {}))
        all_metrics[name] = metrics
        all_reports[name] = report
        _save_confusion_matrix(cm, class_names, name, cfg.plot_dir)
        _save_feature_importance(model, feature_cols, name, cfg.plot_dir)

    # ── VOTING ENSEMBLE ──────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("BUILDING VOTING ENSEMBLE")
    print("=" * 70)

    voting_clf = build_voting_ensemble(trained_models, X_train, y_train)
    v_metrics, v_report, v_cm = evaluate_model(
        voting_clf, X_test, y_test, class_names, "VotingEnsemble"
    )
    v_metrics["train_time_s"] = "N/A"
    all_metrics["VotingEnsemble"] = v_metrics
    all_reports["VotingEnsemble"] = v_report
    trained_models["VotingEnsemble"] = voting_clf
    _save_confusion_matrix(v_cm, class_names, "VotingEnsemble", cfg.plot_dir)

    # ── SELECT BEST MODEL ────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("MODEL COMPARISON")
    print("=" * 70)
    print(f"  {'Model':<22s}  {'Accuracy':>10}  {'F1(wt)':>8}  "
          f"{'F1(macro)':>10}  {'MinClsRec':>10}  {'Worst class':<12}")
    print("  " + "─" * 80)

    best_name = select_best_model(all_metrics)

    for name, m in all_metrics.items():
        mark = "*" if name == best_name else " "
        viable = "" if m["min_class_recall"] >= MIN_CLASS_RECALL else "  REJECTED"
        print(f"{mark} {name:<22s}  {m['accuracy']:>10.4f}  "
              f"{m['f1_weighted']:>8.4f}  {m['f1_macro']:>10.4f}  "
              f"{m['min_class_recall']:>10.4f}  {m['worst_class']:<12}{viable}")

    best_model = trained_models[best_name]
    best = all_metrics[best_name]
    print(
        f"\n  Selected: {best_name}  "
        f"(macro F1={best['f1_macro']:.4f}, "
        f"worst class {best['worst_class']}={best['min_class_recall']:.4f})"
    )

    # ── SAVE BEST + ALL MODELS ───────────────────────────────────────────────
    model_path = os.path.join(cfg.artifact_dir, "model.pkl")
    joblib.dump(best_model, model_path)
    print(f"[SAVE] Best model -> {model_path}")

    for name, model in trained_models.items():
        joblib.dump(model,
                    os.path.join(cfg.artifact_dir, f"model_{name}.pkl"))

    # ── ANOMALY DETECTION LAYER ──────────────────────────────────────────────
    if not cfg.no_anomaly:
        print("\n" + "=" * 70)
        print("TRAINING ANOMALY DETECTION LAYER")
        print("  (Isolation Forest + Autoencoder on BENIGN traffic only)")
        print("=" * 70)

        # Extract scaled BENIGN samples from the balanced training set
        benign_mask = y_train == benign_label
        X_benign    = X_train[benign_mask]
        print(f"  BENIGN training samples: {X_benign.shape[0]:,}")

        anomaly_artifacts = train_anomaly_layer(
            X_benign=X_benign,
            X_all_train=X_train,
            contamination=0.05,
            random_state=RANDOM_STATE,
        )

        # Save anomaly artifacts
        iforest_path = os.path.join(cfg.artifact_dir, "iforest.pkl")
        ae_path      = os.path.join(cfg.artifact_dir, "autoencoder.pkl")
        thresholds_path = os.path.join(cfg.artifact_dir, "anomaly_thresholds.json")

        joblib.dump(anomaly_artifacts["iforest"],    iforest_path)
        joblib.dump(anomaly_artifacts["autoencoder"], ae_path)

        thresholds = {
            "if_threshold": anomaly_artifacts["if_threshold"],
            "ae_threshold": anomaly_artifacts["ae_threshold"],
        }
        with open(thresholds_path, "w") as fh:
            json.dump(thresholds, fh, indent=2)

        print(f"[SAVE] IsolationForest → {iforest_path}")
        print(f"[SAVE] Autoencoder     → {ae_path}")
        print(f"[SAVE] Thresholds      → {thresholds_path}")

        # Quick anomaly evaluation on test set
        print("\n[ANOMALY] Evaluating anomaly layer on test set…")
        _evaluate_anomaly_layer(
            anomaly_artifacts, X_test, y_test, le, class_names
        )
    else:
        print("\n[ANOMALY] Skipped (--no_anomaly flag).")

    # ── EVALUATION REPORT ────────────────────────────────────────────────────
    _save_report(all_metrics, all_reports, class_names,
                 feature_cols, best_name, cfg.artifact_dir)

    # ── MANIFEST ─────────────────────────────────────────────────────────────
    # Written last: it names the served model and records what produced it, so
    # it must describe artifacts that are already on disk.
    from preprocess import DATA_PATH as _DATASET_PATH
    write_manifest(
        save_dir=cfg.artifact_dir,
        best_model_name=best_name,
        all_metrics=all_metrics,
        class_names=class_names,
        feature_cols=feature_cols,
        dataset_path=_DATASET_PATH,
        config={
            "max_rows": cfg.max_rows,
            "top_k":    cfg.top_k,
            "no_dnn":   cfg.no_dnn,
            "no_anomaly": cfg.no_anomaly,
            "balance_strategy": "hybrid",
        },
        anomaly_enabled=not cfg.no_anomaly,
    )

    # ── SUMMARY ──────────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("TRAINING COMPLETE")
    print("=" * 70)
    print(f"  Artifact dir  : {cfg.artifact_dir}")
    print(f"  model.pkl     : best model ({best_name})")
    print("  scaler.pkl    : StandardScaler")
    print("  label_encoder.pkl")
    print("  feature_columns.json")
    if not cfg.no_anomaly:
        print("  iforest.pkl   : Isolation Forest")
        print("  autoencoder.pkl: Autoencoder")
        print("  anomaly_thresholds.json")
    print(f"\n  Figures → {cfg.plot_dir}/")

    return best_model, scaler, le, feature_cols


# ─────────────────────────────────────────────────────────────────────────────
# ANOMALY EVALUATION HELPER
# ─────────────────────────────────────────────────────────────────────────────

def _evaluate_anomaly_layer(anomaly_artifacts, X_test, y_test, le, class_names):
    """
    Report anomaly detection performance on the test set.

    Positive (anomaly) = any non-BENIGN class.
    """
    iforest      = anomaly_artifacts["iforest"]
    ae           = anomaly_artifacts["autoencoder"]
    if_thresh    = anomaly_artifacts["if_threshold"]
    ae_thresh    = anomaly_artifacts["ae_threshold"]

    benign_enc   = le.transform(["BENIGN"])[0]
    y_true_binary = (y_test != benign_enc).astype(int)   # 1=attack, 0=benign

    # Isolation Forest: score_samples < threshold → anomaly
    if_scores   = iforest.score_samples(X_test)
    if_preds    = (if_scores < if_thresh).astype(int)

    # Autoencoder: recon error > threshold → anomaly
    ae_errors   = ae.reconstruction_error(X_test)
    ae_preds    = (ae_errors > ae_thresh).astype(int)

    # Combined (OR gate)
    combined    = ((if_preds == 1) | (ae_preds == 1)).astype(int)

    def _print_binary_metrics(name, y_pred_binary):
        tp = int(((y_pred_binary == 1) & (y_true_binary == 1)).sum())
        fp = int(((y_pred_binary == 1) & (y_true_binary == 0)).sum())
        tn = int(((y_pred_binary == 0) & (y_true_binary == 0)).sum())
        fn = int(((y_pred_binary == 0) & (y_true_binary == 1)).sum())
        recall_att  = tp / max(tp + fn, 1)
        precision_  = tp / max(tp + fp, 1)
        fpr         = fp / max(fp + tn, 1)
        print(f"  {name:<22s}  "
              f"Attack-Recall={recall_att:.3f}  "
              f"Precision={precision_:.3f}  "
              f"FPR={fpr:.3f}  "
              f"TP={tp:,} FP={fp:,} FN={fn:,}")

    print(f"\n  Anomaly detection on {len(y_test):,} test samples "
          f"({y_true_binary.sum():,} attacks, "
          f"{(1-y_true_binary).sum():,} benign):")
    _print_binary_metrics("Isolation Forest",   if_preds)
    _print_binary_metrics("Autoencoder",         ae_preds)
    _print_binary_metrics("Combined (OR gate)",  combined)


if __name__ == "__main__":
    main()