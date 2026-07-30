"""LangGraph-compatible shared state models."""

from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict

from pydantic import BaseModel, ConfigDict, Field

from cyber_surakshya.platform.audit.metadata import AuditRecord
from cyber_surakshya.platform.identifiers.correlation import (
    CorrelationContext,
    CorrelationId,
    SessionId,
    TraceId,
)
from cyber_surakshya.platform.schemas.alert import Alert
from cyber_surakshya.platform.schemas.analysis_result import AnalysisResult
from cyber_surakshya.platform.schemas.decision_result import DecisionResult
from cyber_surakshya.platform.schemas.detection_result import DetectionResult
from cyber_surakshya.platform.schemas.security_event import SecurityEvent


class PlatformSharedState(TypedDict, total=False):
    """
    LangGraph shared state contract for Cyber Surakshya workflows.

    List fields use Annotated reducers so LangGraph merges node outputs
    via append semantics. This TypedDict is the runtime state shape;
    use PlatformStateModel for validation and serialization.

    No workflow or agent logic is defined here — only the state schema.
    """

    correlation_id: CorrelationId
    trace_id: TraceId
    session_id: SessionId

    security_events: Annotated[list[SecurityEvent], operator.add]
    detection_results: Annotated[list[DetectionResult], operator.add]
    analysis_results: Annotated[list[AnalysisResult], operator.add]
    decision_results: Annotated[list[DecisionResult], operator.add]
    alerts: Annotated[list[Alert], operator.add]
    audit_trail: Annotated[list[AuditRecord], operator.add]
    errors: Annotated[list[str], operator.add]

    metadata: dict[str, Any]


class PlatformStateModel(BaseModel):
    """
    Validated Pydantic representation of platform shared state.

    Converts to and from LangGraph TypedDict state for safe ingestion
    and persistence at workflow boundaries.
    """

    model_config = ConfigDict(extra="forbid")

    correlation_id: CorrelationId
    trace_id: TraceId
    session_id: SessionId

    security_events: list[SecurityEvent] = Field(default_factory=list)
    detection_results: list[DetectionResult] = Field(default_factory=list)
    analysis_results: list[AnalysisResult] = Field(default_factory=list)
    decision_results: list[DecisionResult] = Field(default_factory=list)
    alerts: list[Alert] = Field(default_factory=list)
    audit_trail: list[AuditRecord] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_graph_state(self) -> PlatformSharedState:
        """Serialize to a LangGraph-compatible state dictionary."""
        return PlatformSharedState(
            correlation_id=self.correlation_id,
            trace_id=self.trace_id,
            session_id=self.session_id,
            security_events=self.security_events,
            detection_results=self.detection_results,
            analysis_results=self.analysis_results,
            decision_results=self.decision_results,
            alerts=self.alerts,
            audit_trail=self.audit_trail,
            errors=self.errors,
            metadata=self.metadata,
        )

    @classmethod
    def from_graph_state(cls, state: PlatformSharedState) -> PlatformStateModel:
        """Hydrate from LangGraph state, applying schema validation."""
        return cls.model_validate(dict(state))


def create_initial_state(
    context: CorrelationContext | None = None,
    *,
    metadata: dict[str, Any] | None = None,
) -> PlatformStateModel:
    """
    Create an empty validated platform state for a new workflow run.

    Generates correlation, trace, and session IDs when no context is supplied.
    """
    ctx = context or CorrelationContext.create()
    return PlatformStateModel(
        correlation_id=ctx.correlation_id,
        trace_id=ctx.trace_id,
        session_id=ctx.session_id,
        metadata=metadata or {},
    )
