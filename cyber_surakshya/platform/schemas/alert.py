"""Alert schema."""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from cyber_surakshya.platform.audit.metadata import AuditMetadata
from cyber_surakshya.platform.enums.alert_status import AlertStatus
from cyber_surakshya.platform.enums.severity import Severity
from cyber_surakshya.platform.identifiers.correlation import (
    CorrelationId,
    EntityId,
    TraceId,
    generate_alert_id,
    is_valid_uuid,
)
from cyber_surakshya.platform.risk.score import RiskScore
from cyber_surakshya.platform.validation.rules import (
    ensure_severity_matches_risk,
    validate_non_empty_dict_keys,
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Alert(BaseModel):
    """
    Elevated security finding requiring analyst or automated response.

    Alerts aggregate one or more detection results and security events
    under a shared correlation ID.
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra="forbid",
    )

    alert_id: EntityId = Field(default_factory=generate_alert_id)
    correlation_id: CorrelationId
    trace_id: TraceId

    status: AlertStatus = AlertStatus.OPEN
    severity: Severity
    risk_score: RiskScore

    title: str = Field(..., min_length=1, max_length=512)
    description: str | None = Field(default=None, max_length=4096)

    event_ids: list[EntityId] = Field(default_factory=list)
    detection_ids: list[EntityId] = Field(default_factory=list)

    recommended_actions: list[str] = Field(default_factory=list)
    assigned_to: str | None = Field(default=None, max_length=256)

    opened_at: datetime = Field(default_factory=_utc_now)
    updated_at: datetime = Field(default_factory=_utc_now)
    resolved_at: datetime | None = None

    labels: dict[str, str] = Field(default_factory=dict)
    audit: AuditMetadata

    @field_validator("alert_id", "correlation_id", "trace_id")
    @classmethod
    def check_uuid(cls, value: str) -> str:
        if not is_valid_uuid(value):
            raise ValueError(f"Invalid UUID: {value!r}")
        return str(value).lower()

    @field_validator("event_ids", "detection_ids")
    @classmethod
    def check_id_list(cls, value: list[str]) -> list[str]:
        for item in value:
            if not is_valid_uuid(item):
                raise ValueError(f"Invalid UUID in list: {item!r}")
        return [str(item).lower() for item in value]

    @field_validator("recommended_actions")
    @classmethod
    def check_actions(cls, value: list[str]) -> list[str]:
        for action in value:
            if not action.strip():
                raise ValueError("Recommended actions must be non-empty.")
        return value

    @field_validator("labels")
    @classmethod
    def check_labels(cls, value: dict[str, str]) -> dict[str, str]:
        return validate_non_empty_dict_keys(value)

    @field_validator("opened_at", "updated_at", "resolved_at")
    @classmethod
    def ensure_utc(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_alert_consistency(self) -> Alert:
        ensure_severity_matches_risk(self.severity, self.risk_score.value)

        if not self.event_ids and not self.detection_ids:
            raise ValueError(
                "Alert must reference at least one event_id or detection_id."
            )

        terminal_statuses = {
            AlertStatus.RESOLVED,
            AlertStatus.FALSE_POSITIVE,
            AlertStatus.SUPPRESSED,
        }
        if self.status in terminal_statuses and self.resolved_at is None:
            raise ValueError(
                f"Alerts with status {self.status.value} require resolved_at."
            )

        if self.status == AlertStatus.OPEN and self.resolved_at is not None:
            raise ValueError("Open alerts must not have a resolved_at timestamp.")

        return self

    def with_status(
        self,
        status: AlertStatus,
        *,
        updated_by: str,
        resolved_at: datetime | None = None,
    ) -> Alert:
        """Return a copy with an updated lifecycle status."""
        now = _utc_now()
        updates: dict[str, object] = {
            "status": status,
            "updated_at": now,
            "audit": self.audit.touch(updated_by),
        }
        if status in {
            AlertStatus.RESOLVED,
            AlertStatus.FALSE_POSITIVE,
            AlertStatus.SUPPRESSED,
        }:
            updates["resolved_at"] = resolved_at or now
        return self.model_copy(update=updates)
