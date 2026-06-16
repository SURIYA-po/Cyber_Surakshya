"""Correlation ID generation and validation."""

from __future__ import annotations

import uuid
from typing import Annotated

from pydantic import BaseModel, Field, field_validator

UUID_PATTERN = (
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

CorrelationId = Annotated[
    str,
    Field(
        min_length=36,
        max_length=36,
        pattern=UUID_PATTERN,
        description="UUID v4 correlation identifier linking related platform records.",
    ),
]

TraceId = Annotated[
    str,
    Field(
        min_length=36,
        max_length=36,
        pattern=UUID_PATTERN,
        description="UUID v4 trace identifier for distributed workflow tracing.",
    ),
]

SessionId = Annotated[
    str,
    Field(
        min_length=36,
        max_length=36,
        pattern=UUID_PATTERN,
        description="UUID v4 session identifier for a LangGraph workflow run.",
    ),
]

EntityId = Annotated[
    str,
    Field(
        min_length=36,
        max_length=36,
        pattern=UUID_PATTERN,
        description="UUID v4 identifier for a domain entity.",
    ),
]


def generate_correlation_id() -> str:
    """Generate a new correlation ID (UUID v4)."""
    return str(uuid.uuid4())


def generate_trace_id() -> str:
    """Generate a new trace ID (UUID v4)."""
    return str(uuid.uuid4())


def generate_session_id() -> str:
    """Generate a new workflow session ID (UUID v4)."""
    return str(uuid.uuid4())


def generate_event_id() -> str:
    """Generate a new security event ID (UUID v4)."""
    return str(uuid.uuid4())


def generate_detection_id() -> str:
    """Generate a new detection result ID (UUID v4)."""
    return str(uuid.uuid4())


def generate_alert_id() -> str:
    """Generate a new alert ID (UUID v4)."""
    return str(uuid.uuid4())


def is_valid_uuid(value: str) -> bool:
    """Return True if value is a valid UUID string."""
    try:
        uuid.UUID(str(value))
        return True
    except (ValueError, AttributeError, TypeError):
        return False


class CorrelationContext(BaseModel):
    """
    Bundles correlation identifiers propagated through a workflow.

    All IDs are generated together so a single platform run shares one
    correlation, trace, and session context.
    """

    correlation_id: CorrelationId
    trace_id: TraceId
    session_id: SessionId

    @classmethod
    def create(cls) -> CorrelationContext:
        """Create a fresh correlation context with new UUIDs."""
        return cls(
            correlation_id=generate_correlation_id(),
            trace_id=generate_trace_id(),
            session_id=generate_session_id(),
        )

    @field_validator("correlation_id", "trace_id", "session_id")
    @classmethod
    def validate_uuid_fields(cls, value: str) -> str:
        if not is_valid_uuid(value):
            raise ValueError(f"Invalid UUID: {value!r}")
        return str(value).lower()
