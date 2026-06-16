"""Audit metadata attached to platform records."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

SCHEMA_VERSION = "1.0.0"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AuditMetadata(BaseModel):
    """
    Immutable-style audit envelope for traceability and compliance.

    Tracks creation and last modification with actor and source system
    attribution. Timestamps are always stored in UTC.
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra="forbid",
    )

    schema_version: str = Field(
        default=SCHEMA_VERSION,
        description="Version of the audit metadata schema.",
    )
    created_at: datetime = Field(
        default_factory=_utc_now,
        description="UTC timestamp when the record was created.",
    )
    updated_at: datetime = Field(
        default_factory=_utc_now,
        description="UTC timestamp of the last modification.",
    )
    created_by: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Actor or system component that created the record.",
    )
    updated_by: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Actor or system component that last updated the record.",
    )
    source_system: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Originating system identifier (e.g. ids, zeek, platform).",
    )
    tags: dict[str, str] = Field(
        default_factory=dict,
        description="Optional key-value tags for filtering and lineage.",
    )

    @field_validator("created_at", "updated_at")
    @classmethod
    def ensure_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, value: dict[str, str]) -> dict[str, str]:
        for key in value:
            if not key.strip():
                raise ValueError("Audit tag keys must be non-empty.")
        return value

    def touch(self, updated_by: str) -> AuditMetadata:
        """Return a copy with updated_at and updated_by refreshed."""
        return self.model_copy(
            update={"updated_at": _utc_now(), "updated_by": updated_by}
        )


class AuditRecord(BaseModel):
    """Append-only audit log entry for state transitions."""

    model_config = ConfigDict(extra="forbid")

    action: str = Field(..., min_length=1, max_length=128)
    actor: str = Field(..., min_length=1, max_length=256)
    timestamp: datetime = Field(default_factory=_utc_now)
    entity_type: str = Field(..., min_length=1, max_length=64)
    entity_id: str = Field(..., min_length=36, max_length=36)
    details: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def ensure_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
