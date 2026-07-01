"""Generic memory layer models."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from cyber_surakshya.platform.identifiers.correlation import is_valid_uuid


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _validate_non_empty_text(value: str, field_name: str) -> str:
    stripped = value.strip()
    if not stripped:
        raise ValueError(f"{field_name} must not be empty.")
    return stripped


class MemoryRecord(BaseModel):
    """
    Generic stored memory record.

    Domain objects should be referenced by IDs and metadata rather than by
    importing platform schema classes into the memory layer.
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra="forbid",
    )

    record_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    backend: str = Field(default="memory", min_length=1, max_length=64)
    collection: str = Field(default="custom", min_length=1, max_length=128)
    record_type: str = Field(..., min_length=1, max_length=128)

    entity_id: str | None = Field(default=None, min_length=1, max_length=128)
    correlation_id: str | None = Field(default=None, min_length=36, max_length=36)
    trace_id: str | None = Field(default=None, min_length=36, max_length=36)

    content: Any = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)

    created_at: datetime = Field(default_factory=_utc_now)
    updated_at: datetime = Field(default_factory=_utc_now)

    @field_validator("record_id", "backend", "collection", "record_type")
    @classmethod
    def check_non_empty_text(cls, value: str, info) -> str:
        return _validate_non_empty_text(value, info.field_name)

    @field_validator("correlation_id", "trace_id")
    @classmethod
    def check_optional_uuid(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not is_valid_uuid(value):
            raise ValueError(f"Invalid UUID: {value!r}")
        return str(value).lower()

    @field_validator("metadata")
    @classmethod
    def check_metadata_keys(cls, value: dict[str, Any]) -> dict[str, Any]:
        for key in value:
            if not str(key).strip():
                raise ValueError("Metadata keys must be non-empty.")
        return value

    @field_validator("tags")
    @classmethod
    def normalize_tags(cls, value: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        for tag in value:
            stripped = tag.strip()
            if not stripped:
                raise ValueError("Tags must be non-empty.")
            if stripped not in seen:
                normalized.append(stripped)
                seen.add(stripped)
        return normalized

    @field_validator("created_at", "updated_at")
    @classmethod
    def ensure_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


class MemoryQuery(BaseModel):
    """Generic query filters for memory providers."""

    model_config = ConfigDict(extra="forbid")

    record_ids: list[str] | None = None
    record_types: list[str] | None = None
    entity_ids: list[str] | None = None
    correlation_id: str | None = Field(default=None, min_length=36, max_length=36)
    trace_id: str | None = Field(default=None, min_length=36, max_length=36)

    metadata: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)

    created_after: datetime | None = None
    created_before: datetime | None = None
    updated_after: datetime | None = None
    updated_before: datetime | None = None

    order_by: Literal["created_at", "updated_at"] = "created_at"
    descending: bool = False
    limit: int | None = Field(default=None, ge=1)

    @field_validator("correlation_id", "trace_id")
    @classmethod
    def check_optional_uuid(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not is_valid_uuid(value):
            raise ValueError(f"Invalid UUID: {value!r}")
        return str(value).lower()

    @field_validator("metadata")
    @classmethod
    def check_metadata_keys(cls, value: dict[str, Any]) -> dict[str, Any]:
        for key in value:
            if not str(key).strip():
                raise ValueError("Metadata keys must be non-empty.")
        return value

    @field_validator("tags")
    @classmethod
    def normalize_tags(cls, value: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        for tag in value:
            stripped = tag.strip()
            if not stripped:
                raise ValueError("Tags must be non-empty.")
            if stripped not in seen:
                normalized.append(stripped)
                seen.add(stripped)
        return normalized

    @field_validator(
        "created_after", "created_before", "updated_after", "updated_before"
    )
    @classmethod
    def ensure_utc(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


class MemorySearchResult(BaseModel):
    """A memory search hit."""

    model_config = ConfigDict(extra="forbid")

    record: MemoryRecord
    score: float | None = Field(default=None, ge=0.0, le=1.0)
