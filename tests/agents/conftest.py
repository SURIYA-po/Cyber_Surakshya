"""Shared fixtures for agent tests."""
from __future__ import annotations

from dataclasses import replace

import pytest

from agents.response.config import ResponsePolicyConfig
from cyber_surakshya.platform.actions.action import Action
from cyber_surakshya.platform.actions.action_parameters import ActionParameters
from cyber_surakshya.platform.actions.action_target import ActionTarget
from cyber_surakshya.platform.actions.action_type import ActionType
from cyber_surakshya.platform.audit.metadata import AuditMetadata
from cyber_surakshya.platform.identifiers.correlation import (
    CorrelationContext,
    generate_analysis_id,
    generate_detection_id,
    generate_event_id,
)
from cyber_surakshya.platform.schemas.decision_result import (
    ApprovalStatus,
    DecisionPriority,
    DecisionResult,
    DecisionStatus,
)
from cyber_surakshya.platform.schemas.response_result import EngineTrustTier
from cyber_surakshya.platform.state import PlatformSharedState, create_initial_state

# Engine names used across the response tests.
DETERMINISTIC_ENGINE = "DeterministicDecisionEngine"
LLM_ENGINE           = "OllamaDecisionEngine"
UNREGISTERED_ENGINE  = "SomeBrandNewEngine"


def make_decision(
    *,
    action_type: ActionType = ActionType.BLOCK_IP,
    target_type: str = "IP",
    target_value: str = "203.0.113.10",
    asset_criticality: str | None = None,
    duration_seconds: int | None = None,
    dry_run: bool = False,
    decision_engine: str = DETERMINISTIC_ENGINE,
    confidence: float = 0.95,
    requires_approval: bool = False,
    approval_status: ApprovalStatus = ApprovalStatus.AUTO_APPROVED,
    correlation_context: CorrelationContext | None = None,
) -> DecisionResult:
    """Build a DecisionResult with sensible, overridable defaults."""
    ctx = correlation_context or CorrelationContext.create()
    return DecisionResult(
        analysis_id=generate_analysis_id(),
        detection_id=generate_detection_id(),
        event_id=generate_event_id(),
        correlation_id=ctx.correlation_id,
        trace_id=ctx.trace_id,
        action=Action(
            action_type=action_type,
            target=ActionTarget(
                target_type=target_type,
                target_value=target_value,
                asset_criticality=asset_criticality,
            ),
            parameters=ActionParameters(
                duration_seconds=duration_seconds,
                dry_run=dry_run,
            ),
        ),
        priority=DecisionPriority.CRITICAL,
        status=(
            DecisionStatus.WAITING_APPROVAL
            if requires_approval
            else DecisionStatus.READY_FOR_EXECUTION
        ),
        requires_approval=requires_approval,
        approval_status=approval_status,
        rationale="Test decision rationale.",
        confidence=confidence,
        policy_version="1.0.0",
        decision_engine=decision_engine,
        engine_version="1.0.0",
        policy_name="test_policy_rule",
        decision_duration_ms=1.0,
        memory_hits=0,
        audit=AuditMetadata(
            created_by="decision_agent",
            updated_by="decision_agent",
            source_system="decision_pipeline",
        ),
    )


def make_state(*decisions: DecisionResult) -> PlatformSharedState:
    """Build a graph state carrying the given decisions."""
    ctx = CorrelationContext(
        correlation_id=decisions[0].correlation_id,
        trace_id=decisions[0].trace_id,
        session_id=CorrelationContext.create().session_id,
    ) if decisions else None
    state = create_initial_state(context=ctx)
    state.decision_results = list(decisions)
    return state.to_graph_state()


@pytest.fixture
def policy() -> ResponsePolicyConfig:
    """A deterministic policy with a registered LLM engine.

    Built from explicit values rather than the shipped YAML so the tests
    assert against known thresholds regardless of local configuration.
    """
    base = ResponsePolicyConfig()
    return replace(
        base,
        engine_trust={
            DETERMINISTIC_ENGINE: EngineTrustTier.DETERMINISTIC,
            LLM_ENGINE:           EngineTrustTier.AI_SUPERVISED,
        },
        source_path="test_policy",
        loaded_from_defaults=False,
    )
