"""Security event schema."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from cyber_surakshya.platform.audit.metadata import AuditMetadata
from cyber_surakshya.platform.enums.event_source import EventSource
from cyber_surakshya.platform.enums.event_type import EventType
from cyber_surakshya.platform.enums.severity import Severity
from cyber_surakshya.platform.identifiers.correlation import (
    CorrelationId,
    EntityId,
    TraceId,
    generate_event_id,
    is_valid_uuid,
)
from cyber_surakshya.platform.risk.score import RiskScore
from cyber_surakshya.platform.validation.rules import (
    ensure_severity_matches_risk,
    validate_ip_address,
    validate_non_empty_dict_keys,
    validate_port,
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class NetworkEndpoint(BaseModel):
    """Network addressing details for flow-based events."""

    model_config = ConfigDict(extra="forbid")

    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = Field(default=None, max_length=16)

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def check_ip(cls, value: str | None) -> str | None:
        return validate_ip_address(value)

    @field_validator("source_port", "destination_port")
    @classmethod
    def check_port(cls, value: int | None) -> int | None:
        return validate_port(value)


class SecurityEvent(BaseModel):
    """
    Canonical schema for a security-relevant observation.

    Represents raw or normalized telemetry (network flows, auth attempts,
    etc.) before or after detection enrichment. Designed to interoperate
    with the existing IDS pipeline via optional raw_payload and features.
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra="forbid",
    )

    event_id: EntityId = Field(default_factory=generate_event_id)
    correlation_id: CorrelationId
    trace_id: TraceId

    event_type: EventType
    source: EventSource
    severity: Severity
    risk_score: RiskScore

    title: str = Field(..., min_length=1, max_length=512)
    description: str | None = Field(default=None, max_length=4096)

    observed_at: datetime = Field(
        default_factory=_utc_now,
        description="UTC timestamp when the observation occurred.",
    )
    ingested_at: datetime = Field(
        default_factory=_utc_now,
        description="UTC timestamp when the platform ingested the event.",
    )

    network: NetworkEndpoint | None = None
    raw_payload: dict[str, Any] = Field(default_factory=dict)
    features: dict[str, float] = Field(default_factory=dict)
    labels: dict[str, str] = Field(default_factory=dict)
    audit: AuditMetadata

    @field_validator("event_id", "correlation_id", "trace_id")
    @classmethod
    def check_uuid(cls, value: str) -> str:
        if not is_valid_uuid(value):
            raise ValueError(f"Invalid UUID: {value!r}")
        return str(value).lower()

    @field_validator("observed_at", "ingested_at")
    @classmethod
    def ensure_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @field_validator("raw_payload", "features", "labels")
    @classmethod
    def check_dict_keys(cls, value: dict[str, Any]) -> dict[str, Any]:
        return validate_non_empty_dict_keys(value)

    @model_validator(mode="after")
    def validate_severity_alignment(self) -> SecurityEvent:
        ensure_severity_matches_risk(self.severity, self.risk_score.value)
        return self
