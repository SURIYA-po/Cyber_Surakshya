"""Adapter from the existing IDS inference pipeline to DetectionResult."""

from __future__ import annotations

import logging
import math
import os
from dataclasses import dataclass
from typing import Any, Callable, Sequence

import pandas as pd

import inference
from adapters.detection.base import DetectionAdapter
from cyber_surakshya.platform.audit.metadata import AuditMetadata
from cyber_surakshya.platform.enums.detection_status import DetectionStatus
from cyber_surakshya.platform.identifiers.correlation import (
    generate_correlation_id,
    generate_event_id,
    generate_trace_id,
)
from cyber_surakshya.platform.risk.score import RiskScore, severity_from_risk_score
from cyber_surakshya.platform.schemas.detection_result import DetectionResult

logger = logging.getLogger(__name__)

ArtifactLoader = Callable[..., tuple[Any, Any, Any, Sequence[str]]]


# ── Risk model ────────────────────────────────────────────────────────────────
# Base risk per attack class, before confidence weighting.
#
# Risk used to be `confidence * 100`, which made it a pure restatement of how
# sure the model was — attack class was ignored entirely. Because the model is
# >99% confident on its easy classes, every detection landed at risk >= 80,
# which is DecisionRule 1's threshold for BLOCK_IP with `requires_approval=
# False`. A routine port scan and a volumetric DDoS both produced an
# unapproved automatic block.
#
# These values encode consequence, not detectability:
#   BOTNET      — C2 beaconing means a host is already compromised.
#   WEBATTACK   — SQLi/XSS is a data-breach vector.
#   DDOS / DOS  — availability impact, no compromise implied.
#   BRUTEFORCE  — credential attack, usually unsuccessful and very noisy.
#   PORTSCAN    — reconnaissance. Constant background noise on any public
#                 interface; auto-blocking every scanner is self-harm.
DEFAULT_ATTACK_BASE_RISK: dict[str, float] = {
    "BOTNET":       95.0,
    "INFILTRATION": 95.0,   # not in the current 7-class model; reserved
    "WEBATTACK":    90.0,
    "DDOS":         85.0,
    "DOS":          75.0,
    "BRUTEFORCE":   70.0,
    "PORTSCAN":     40.0,
}

# Applied to a label the table does not know — a retrained model with new
# classes scores mid-range rather than defaulting to "harmless" or "critical".
UNKNOWN_ATTACK_BASE_RISK = 60.0

# A non-benign label the classifier is not confident enough to stand behind.
INCONCLUSIVE_RISK_FACTOR = 0.5

# The classifier said BENIGN but the unsupervised anomaly layer disagreed.
# There is no attack label to price, so this is a fixed "worth a look" score
# that maps to MODERATE risk and routes to SOC review, not containment.
ANOMALY_ONLY_RISK = 45.0


@dataclass(frozen=True)
class IDSArtifacts:
    """Loaded IDS model artifacts required by inference.py.

    The anomaly layer is optional. When present, ``inference.predict`` runs
    Isolation Forest and autoencoder reconstruction error alongside the
    supervised classifier and this adapter reports the combined verdict.
    """

    model: Any
    scaler: Any
    label_encoder: Any
    feature_columns: Sequence[str]

    iforest: Any = None
    autoencoder: Any = None
    if_threshold: float | None = None
    ae_threshold: float | None = None

    @property
    def anomaly_ready(self) -> bool:
        """True when ``inference.predict`` can run the unsupervised layer.

        Read by ``inference.predict`` via getattr, which is why this mirrors
        the attribute name on ``inference.IDSArtifacts``.
        """
        return (
            self.iforest is not None
            and self.autoencoder is not None
            and self.if_threshold is not None
            and self.ae_threshold is not None
        )


class IDSDetectionAdapter(DetectionAdapter):
    """
    Bridge raw IDS flow features into a validated DetectionResult.

    This adapter intentionally depends on the existing inference module for
    artifact loading, preprocessing, model prediction, and probability output.
    """

    def __init__(
        self,
        *,
        artifacts: IDSArtifacts | None = None,
        artifact_dir: str | os.PathLike[str] | None = None,
        artifact_loader: ArtifactLoader = inference.load_artifacts,
        model_name: str | None = None,
        model_version: str = "1.0.0",
        benign_label: str = "BENIGN",
        min_detection_confidence: float = 0.5,
        attack_base_risk: dict[str, float] | None = None,
        min_feature_coverage: float = inference.DEFAULT_MIN_FEATURE_COVERAGE,
    ) -> None:
        """
        Args:
            attack_base_risk: per-class base risk, keyed by upper-case label.
                Defaults to DEFAULT_ATTACK_BASE_RISK. Override to retune
                without editing this module.
            min_feature_coverage: fraction of model features that must be
                present in the incoming flow. Below it, detection raises
                rather than predicting on a mostly zero-filled vector.
        """
        if not 0.0 <= min_detection_confidence <= 1.0:
            raise ValueError("min_detection_confidence must be between 0.0 and 1.0.")
        if not 0.0 <= min_feature_coverage <= 1.0:
            raise ValueError("min_feature_coverage must be between 0.0 and 1.0.")

        self._artifact_dir = os.fspath(artifact_dir) if artifact_dir else None
        self._artifact_loader = artifact_loader
        self._artifacts = artifacts
        self._model_name = model_name
        self._model_version = model_version
        self._benign_label = benign_label
        self._min_detection_confidence = min_detection_confidence
        self._attack_base_risk = dict(
            attack_base_risk if attack_base_risk is not None
            else DEFAULT_ATTACK_BASE_RISK
        )
        self._min_feature_coverage = min_feature_coverage

    def detect(self, flow_data: dict[str, Any]) -> DetectionResult:
        """Run IDS inference for one raw flow record."""
        validated_flow = self._validate_flow_data(flow_data)
        artifacts = self._get_artifacts()

        logger.info(
            "ids_detection_started",
            extra={
                "detector": "ids",
                "feature_count": len(validated_flow),
                "model_name": self._resolved_model_name(artifacts.model),
            },
        )

        raw_df = pd.DataFrame([validated_flow])
        # predict_dual_layer, explicitly. This used to call inference.predict
        # with unpacked (model, scaler, le, feature_cols) arguments, a form
        # that silently hard-codes anomaly_ready=False -- so the Isolation
        # Forest and autoencoder were loaded at startup and never consulted
        # for any detection the platform made. The function name now states
        # which layers run.
        prediction_df = inference.predict_dual_layer(
            raw_df,
            artifacts,
            return_proba=True,
            min_coverage=self._min_feature_coverage,
            context="IDS detection",
        )

        if len(prediction_df) != 1:
            raise ValueError(
                f"IDS inference must return exactly one prediction, got {len(prediction_df)}."
            )

        row = prediction_df.iloc[0]
        predicted_label = str(row["prediction"])
        confidence = self._as_probability(row.get("confidence", 1.0), "confidence")
        probabilities = self._extract_probabilities(row)
        anomaly_detected = bool(row.get("is_anomaly", False))
        status = self._status_for(predicted_label, confidence, anomaly_detected)
        risk_score = self._risk_score_for(
            status, predicted_label, confidence, anomaly_detected
        )
        severity = severity_from_risk_score(risk_score.value)

        result = DetectionResult(
            event_id=generate_event_id(),
            correlation_id=generate_correlation_id(),
            trace_id=generate_trace_id(),
            status=status,
            severity=severity,
            risk_score=risk_score,
            model_name=self._resolved_model_name(artifacts.model),
            model_version=self._model_version,
            predicted_label=predicted_label,
            confidence=confidence,
            probabilities=probabilities,
            # The unsupervised layer's verdict, NOT a restatement of "the
            # classifier said attack". Previously this was
            # `status == DETECTED`, so anything reading it as an anomaly
            # signal — including DecisionRule 5's rationale — was misled.
            is_anomaly=anomaly_detected,
            benign_label=self._benign_label,
            feature_snapshot=self._numeric_feature_snapshot(validated_flow),
            metadata={
                "adapter": "ids_detection_adapter",
                "detector_type": "ids",
                "inference_module": "inference.py",
                "anomaly_layer": "active" if artifacts.anomaly_ready else "unavailable",
                "if_anomaly": bool(row.get("if_anomaly", False)),
                "ae_anomaly": bool(row.get("ae_anomaly", False)),
            },
            audit=AuditMetadata(
                created_by="ids_detection_adapter",
                updated_by="ids_detection_adapter",
                source_system="ids",
            ),
        )

        logger.info(
            "ids_detection_completed",
            extra={
                "detector": "ids",
                "detection_id": result.detection_id,
                "status": result.status.value,
                "predicted_label": result.predicted_label,
                "confidence": result.confidence,
                "risk_score": result.risk_score.value,
            },
        )
        return result

    def _get_artifacts(self) -> IDSArtifacts:
        if self._artifacts is not None:
            return self._artifacts

        logger.info(
            "ids_artifacts_loading",
            extra={"detector": "ids", "artifact_dir": self._artifact_dir},
        )
        if self._artifact_dir:
            model_path = os.path.join(self._artifact_dir, "model.pkl")
            scaler_path = os.path.join(self._artifact_dir, "scaler.pkl")
            le_path = os.path.join(self._artifact_dir, "label_encoder.pkl")
            feat_path = os.path.join(self._artifact_dir, "feature_columns.json")
            loaded = self._artifact_loader(model_path, scaler_path, le_path, feat_path)
            anomaly = inference.load_anomaly_layer(
                os.path.join(self._artifact_dir, "iforest.pkl"),
                os.path.join(self._artifact_dir, "autoencoder.pkl"),
                os.path.join(self._artifact_dir, "anomaly_thresholds.json"),
            )
        else:
            loaded = self._artifact_loader()
            anomaly = inference.load_anomaly_layer()

        iforest, autoencoder, if_threshold, ae_threshold = anomaly
        self._artifacts = IDSArtifacts(
            *loaded,
            iforest=iforest,
            autoencoder=autoencoder,
            if_threshold=if_threshold,
            ae_threshold=ae_threshold,
        )
        if not self._artifacts.anomaly_ready:
            # Supervised-only is a degraded mode, not a failure — but it must
            # be visible, because INCONCLUSIVE-on-anomaly becomes unreachable.
            logger.warning(
                "ids_anomaly_layer_unavailable",
                extra={
                    "detector": "ids",
                    "artifact_dir": self._artifact_dir,
                    "impact": "novel-attack detection degraded to supervised only",
                },
            )
        logger.info(
            "ids_artifacts_loaded",
            extra={
                "detector": "ids",
                "model_name": self._resolved_model_name(self._artifacts.model),
                "feature_count": len(self._artifacts.feature_columns),
                "anomaly_ready": self._artifacts.anomaly_ready,
            },
        )
        return self._artifacts

    def _resolved_model_name(self, model: Any) -> str:
        return self._model_name or type(model).__name__

    def _validate_flow_data(self, flow_data: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(flow_data, dict):
            raise TypeError("flow_data must be a dict[str, Any].")
        if not flow_data:
            raise ValueError("flow_data must not be empty.")

        validated: dict[str, Any] = {}
        for key, value in flow_data.items():
            key_text = str(key).strip()
            if not key_text:
                raise ValueError("flow_data keys must be non-empty strings.")
            validated[key_text] = value
        return validated

    def _extract_probabilities(self, row: pd.Series) -> dict[str, float]:
        probabilities: dict[str, float] = {}
        for column, value in row.items():
            if not str(column).startswith("prob_"):
                continue
            label = str(column)[len("prob_") :]
            probabilities[label] = self._as_probability(value, column)
        return probabilities

    def _status_for(
        self,
        predicted_label: str,
        confidence: float,
        anomaly_detected: bool,
    ) -> DetectionStatus:
        """Combine the supervised label with the unsupervised anomaly verdict.

        The BENIGN + anomaly case is the whole point of training a second,
        unsupervised layer: the classifier can only choose among the seven
        classes it was trained on, so a novel attack is confidently sorted
        into the nearest known class — or into BENIGN. When the anomaly layer
        disagrees with a BENIGN verdict, the honest answer is "uncertain",
        not "safe".
        """
        if predicted_label.upper() == self._benign_label.upper():
            if anomaly_detected:
                return DetectionStatus.INCONCLUSIVE
            return DetectionStatus.BENIGN
        if confidence < self._min_detection_confidence:
            return DetectionStatus.INCONCLUSIVE
        return DetectionStatus.DETECTED

    def _base_risk_for(self, predicted_label: str) -> float:
        """Base risk for an attack class, before confidence weighting."""
        return self._attack_base_risk.get(
            predicted_label.strip().upper(), UNKNOWN_ATTACK_BASE_RISK
        )

    def _risk_score_for(
        self,
        status: DetectionStatus,
        predicted_label: str,
        confidence: float,
        anomaly_detected: bool,
    ) -> RiskScore:
        """Score consequence × certainty, not certainty alone."""
        if status == DetectionStatus.BENIGN:
            return RiskScore(value=0.0, rationale="IDS classified the flow as benign.")

        if status == DetectionStatus.INCONCLUSIVE:
            if predicted_label.upper() == self._benign_label.upper():
                return RiskScore(
                    value=ANOMALY_ONLY_RISK,
                    rationale=(
                        "Supervised classifier reported benign, but the "
                        "unsupervised anomaly layer flagged this flow as "
                        "out of distribution. Warrants analyst review."
                    ),
                )
            base = self._base_risk_for(predicted_label)
            return RiskScore(
                value=round(base * confidence * INCONCLUSIVE_RISK_FACTOR, 4),
                rationale=(
                    f"IDS returned {predicted_label} below the "
                    f"{self._min_detection_confidence:.0%} confidence "
                    f"threshold (base risk {base:.0f})."
                ),
            )

        base = self._base_risk_for(predicted_label)
        value = base * confidence
        rationale = (
            f"{predicted_label} at {confidence:.0%} confidence "
            f"(class base risk {base:.0f}/100)."
        )
        if anomaly_detected:
            # Both layers agree independently. Move a fixed fraction of the
            # remaining headroom rather than a fixed number of points, so the
            # bump cannot push a low-consequence class into CRITICAL on its own.
            value += (100.0 - value) * 0.25
            rationale += " Unsupervised anomaly layer concurs."
        return RiskScore(
            value=round(min(value, 100.0), 4),
            rationale=rationale,
        )

    def _numeric_feature_snapshot(self, flow_data: dict[str, Any]) -> dict[str, float]:
        snapshot: dict[str, float] = {}
        for key, value in flow_data.items():
            try:
                numeric = float(value)
            except (TypeError, ValueError):
                continue
            if math.isfinite(numeric):
                snapshot[key] = numeric
        return snapshot

    def _as_probability(self, value: Any, field_name: str) -> float:
        try:
            probability = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{field_name} must be numeric.") from exc
        if not 0.0 <= probability <= 1.0:
            raise ValueError(f"{field_name} must be between 0.0 and 1.0.")
        return round(probability, 6)
