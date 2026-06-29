"""Analysis result schema."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from cyber_surakshya.platform.audit.metadata import AuditMetadata
from cyber_surakshya.platform.enums.severity import Severity
from cyber_surakshya.platform.identifiers.correlation import (
    CorrelationId,
    EntityId,
    TraceId,
    generate_analysis_id,
    is_valid_uuid,
)
from cyber_surakshya.platform.risk.score import RiskScore
from cyber_surakshya.platform.validation.rules import (
    ensure_severity_matches_risk,
    validate_confidence,
    validate_non_empty_dict_keys,
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AnalysisEvidence(BaseModel):
    """Single evidence item used by an analysis result."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    source: str = Field(..., min_length=1, max_length=128)
    name: str = Field(..., min_length=1, max_length=128)
    value: str | int | float | bool
    description: str | None = Field(default=None, max_length=1024)


class AnalysisResult(BaseModel):
    """Structured reasoning output produced from a detection result."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra="forbid",
    )

    analysis_id: EntityId = Field(default_factory=generate_analysis_id)
    event_id: EntityId
    detection_id: EntityId
    correlation_id: CorrelationId
    trace_id: TraceId

    severity: Severity
    risk_score: RiskScore

    summary: str = Field(..., min_length=1, max_length=1024)
    reasoning: str = Field(..., min_length=1, max_length=4096)
    evidence: list[AnalysisEvidence] = Field(default_factory=list)
    confidence: float = Field(..., ge=0.0, le=1.0)
    uncertainty: list[str] = Field(default_factory=list)

    metadata: dict[str, Any] = Field(default_factory=dict)
    analyzed_at: datetime = Field(default_factory=_utc_now)
    audit: AuditMetadata

    @field_validator(
        "analysis_id", "event_id", "detection_id", "correlation_id", "trace_id"
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

    @field_validator("metadata")
    @classmethod
    def check_metadata_keys(cls, value: dict[str, Any]) -> dict[str, Any]:
        return validate_non_empty_dict_keys(value)

    @field_validator("uncertainty")
    @classmethod
    def check_uncertainty(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item.strip():
                raise ValueError("Uncertainty entries must be non-empty.")
        return value

    @field_validator("analyzed_at")
    @classmethod
    def ensure_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_analysis_consistency(self) -> AnalysisResult:
        ensure_severity_matches_risk(self.severity, self.risk_score.value)
        return self
