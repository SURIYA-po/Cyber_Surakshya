"""Detection result schema."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from cyber_surakshya.platform.audit.metadata import AuditMetadata
from cyber_surakshya.platform.enums.detection_status import DetectionStatus
from cyber_surakshya.platform.enums.severity import Severity
from cyber_surakshya.platform.identifiers.correlation import (
    CorrelationId,
    EntityId,
    TraceId,
    generate_detection_id,
    is_valid_uuid,
)
from cyber_surakshya.platform.risk.score import RiskScore
from cyber_surakshya.platform.validation.rules import (
    ensure_severity_matches_risk,
    validate_confidence,
    validate_non_empty_dict_keys,
    validate_probability_map,
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class DetectionResult(BaseModel):
    """
    Structured output from a detection pipeline (e.g. IDS inference).

    This schema defines the contract for detection outputs. No detection
    agent or workflow is implemented in this component.
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra="forbid",
    )

    detection_id: EntityId = Field(default_factory=generate_detection_id)
    event_id: EntityId
    correlation_id: CorrelationId
    trace_id: TraceId

    status: DetectionStatus
    severity: Severity
    risk_score: RiskScore

    model_name: str = Field(..., min_length=1, max_length=128)
    model_version: str = Field(..., min_length=1, max_length=64)

    predicted_label: str = Field(..., min_length=1, max_length=128)
    confidence: float = Field(..., ge=0.0, le=1.0)
    probabilities: dict[str, float] = Field(default_factory=dict)

    is_anomaly: bool = False
    benign_label: str = Field(default="BENIGN", max_length=128)

    feature_snapshot: dict[str, float] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    detected_at: datetime = Field(default_factory=_utc_now)
    audit: AuditMetadata

    @field_validator(
        "detection_id", "event_id", "correlation_id", "trace_id"
    )
    @classmethod
    def check_uuid(cls, value: str) -> str:
        if not is_valid_uuid(value):
            raise ValueError(f"Invalid UUID: {value!r}")
        return str(value).lower()

    @field_validator("confidence")
    @classmethod
    def check_confidence(cls, value: float) -> float:
        return validate_confidence(value)

    @field_validator("probabilities")
    @classmethod
    def check_probabilities(cls, value: dict[str, float]) -> dict[str, float]:
        if not value:
            return value
        return validate_probability_map(value)

    @field_validator("feature_snapshot", "metadata")
    @classmethod
    def check_dict_keys(cls, value: dict[str, Any]) -> dict[str, Any]:
        return validate_non_empty_dict_keys(value)

    @field_validator("detected_at")
    @classmethod
    def ensure_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_detection_consistency(self) -> DetectionResult:
        ensure_severity_matches_risk(self.severity, self.risk_score.value)

        if self.status == DetectionStatus.BENIGN and self.is_anomaly:
            raise ValueError("Benign detections cannot be flagged as anomalies.")

        if self.status == DetectionStatus.DETECTED:
            if self.predicted_label.upper() == self.benign_label.upper():
                raise ValueError(
                    "Detected status requires a non-benign predicted label."
                )

        return self
