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


@dataclass(frozen=True)
class IDSArtifacts:
    """Loaded IDS model artifacts required by inference.py."""

    model: Any
    scaler: Any
    label_encoder: Any
    feature_columns: Sequence[str]


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
    ) -> None:
        if not 0.0 <= min_detection_confidence <= 1.0:
            raise ValueError("min_detection_confidence must be between 0.0 and 1.0.")

        self._artifact_dir = os.fspath(artifact_dir) if artifact_dir else None
        self._artifact_loader = artifact_loader
        self._artifacts = artifacts
        self._model_name = model_name
        self._model_version = model_version
        self._benign_label = benign_label
        self._min_detection_confidence = min_detection_confidence

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
        prediction_df = inference.predict(
            raw_df,
            artifacts.model,
            artifacts.scaler,
            artifacts.label_encoder,
            artifacts.feature_columns,
            return_proba=True,
        )

        if len(prediction_df) != 1:
            raise ValueError(
                f"IDS inference must return exactly one prediction, got {len(prediction_df)}."
            )

        row = prediction_df.iloc[0]
        predicted_label = str(row["prediction"])
        confidence = self._as_probability(row.get("confidence", 1.0), "confidence")
        probabilities = self._extract_probabilities(row)
        status = self._status_for(predicted_label, confidence)
        risk_score = self._risk_score_for(status, confidence)
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
            is_anomaly=status == DetectionStatus.DETECTED,
            benign_label=self._benign_label,
            feature_snapshot=self._numeric_feature_snapshot(validated_flow),
            metadata={
                "adapter": "ids_detection_adapter",
                "detector_type": "ids",
                "inference_module": "inference.py",
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
        else:
            loaded = self._artifact_loader()

        self._artifacts = IDSArtifacts(*loaded)
        logger.info(
            "ids_artifacts_loaded",
            extra={
                "detector": "ids",
                "model_name": self._resolved_model_name(self._artifacts.model),
                "feature_count": len(self._artifacts.feature_columns),
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

    def _status_for(self, predicted_label: str, confidence: float) -> DetectionStatus:
        if predicted_label.upper() == self._benign_label.upper():
            return DetectionStatus.BENIGN
        if confidence < self._min_detection_confidence:
            return DetectionStatus.INCONCLUSIVE
        return DetectionStatus.DETECTED

    def _risk_score_for(
        self,
        status: DetectionStatus,
        confidence: float,
    ) -> RiskScore:
        if status == DetectionStatus.BENIGN:
            return RiskScore(value=0.0, rationale="IDS classified the flow as benign.")
        if status == DetectionStatus.INCONCLUSIVE:
            return RiskScore(
                value=round(confidence * 50.0, 4),
                rationale="IDS returned a non-benign label below confidence threshold.",
            )
        return RiskScore(
            value=round(confidence * 100.0, 4),
            rationale="IDS classified the flow as non-benign.",
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
