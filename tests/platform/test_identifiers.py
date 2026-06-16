"""Tests for correlation and trace identifiers."""

import uuid

import pytest
from pydantic import ValidationError

from cyber_surakshya.platform.identifiers.correlation import (
    CorrelationContext,
    generate_correlation_id,
    is_valid_uuid,
)


def test_generate_correlation_id_is_valid_uuid():
    value = generate_correlation_id()
    assert is_valid_uuid(value)
    uuid.UUID(value)


def test_correlation_context_create_generates_unique_ids():
    ctx = CorrelationContext.create()
    assert is_valid_uuid(ctx.correlation_id)
    assert is_valid_uuid(ctx.trace_id)
    assert is_valid_uuid(ctx.session_id)
    assert len({ctx.correlation_id, ctx.trace_id, ctx.session_id}) == 3


def test_correlation_context_rejects_invalid_uuid():
    with pytest.raises(ValidationError):
        CorrelationContext(
            correlation_id="not-a-valid-uuid",
            trace_id=generate_correlation_id(),
            session_id=generate_correlation_id(),
        )
