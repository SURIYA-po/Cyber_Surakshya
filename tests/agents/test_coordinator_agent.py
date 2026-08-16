"""Tests for CoordinatorAgent routing, draining, and termination safety."""
from __future__ import annotations

import pytest

from agents.coordinator.coordinator_agent import CoordinatorAgent
from agents.coordinator.routing import (
    COORDINATOR_METADATA_KEY,
    CoordinatorMemo,
    RouteTarget,
    build_work_queue,
    decide_route,
    find_duplicate_event_ids,
)
from cyber_surakshya.platform.audit.metadata import AuditMetadata
from cyber_surakshya.platform.enums.detection_status import DetectionStatus
from cyber_surakshya.platform.enums.event_source import EventSource
from cyber_surakshya.platform.enums.event_type import EventType
from cyber_surakshya.platform.enums.severity import Severity
from cyber_surakshya.platform.identifiers.correlation import (
    CorrelationContext,
    generate_analysis_id,
    generate_detection_id,
    generate_event_id,
)
from cyber_surakshya.platform.risk.score import RiskScore
from cyber_surakshya.platform.schemas.analysis_result import AnalysisResult
from cyber_surakshya.platform.schemas.decision_result import ApprovalStatus
from cyber_surakshya.platform.schemas.detection_result import DetectionResult
from cyber_surakshya.platform.schemas.response_result import (
    EngineTrustTier,
    GuardVerdict,
    ResponseResult,
    ResponseStatus,
)
from cyber_surakshya.platform.schemas.security_event import (
    NetworkEndpoint,
    SecurityEvent,
)
from cyber_surakshya.platform.state import PlatformStateModel, create_initial_state
from tests.agents.conftest import make_decision

_AUDIT = AuditMetadata(created_by="t", updated_by="t", source_system="t")


# ── Builders ──────────────────────────────────────────────────────────────────


def _event(ctx: CorrelationContext, index: int = 0) -> SecurityEvent:
    return SecurityEvent(
        event_id=generate_event_id(),
        correlation_id=ctx.correlation_id,
        trace_id=ctx.trace_id,
        event_type=EventType.NETWORK_FLOW,
        source=EventSource.IDS,
        severity=Severity.INFO,
        risk_score=RiskScore(value=0.0),
        title=f"flow {index}",
        network=NetworkEndpoint(
            source_ip=f"203.0.113.{index + 1}",
            destination_ip="10.0.0.1",
            destination_port=80,
        ),
        features={"Destination Port": 80.0},
        audit=_AUDIT,
    )


def _detection(ctx: CorrelationContext, event: SecurityEvent) -> DetectionResult:
    return DetectionResult(
        detection_id=generate_detection_id(),
        event_id=event.event_id,
        correlation_id=ctx.correlation_id,
        trace_id=ctx.trace_id,
        status=DetectionStatus.DETECTED,
        severity=Severity.HIGH,
        risk_score=RiskScore(value=70.0),
        model_name="test-model",
        model_version="1.0.0",
        predicted_label="DDOS",
        confidence=0.9,
        audit=_AUDIT,
    )


def _analysis(ctx: CorrelationContext, detection: DetectionResult) -> AnalysisResult:
    return AnalysisResult(
        analysis_id=generate_analysis_id(),
        event_id=detection.event_id,
        detection_id=detection.detection_id,
        correlation_id=ctx.correlation_id,
        trace_id=ctx.trace_id,
        severity=Severity.HIGH,
        risk_score=RiskScore(value=70.0),
        summary="test summary",
        reasoning="test reasoning",
        confidence=0.9,
        audit=_AUDIT,
    )


def _awaiting_response(decision) -> ResponseResult:
    return ResponseResult(
        decision_id=decision.decision_id,
        correlation_id=decision.correlation_id,
        trace_id=decision.trace_id,
        action=decision.action,
        original_action=decision.action,
        status=ResponseStatus.AWAITING_APPROVAL,
        guard_verdict=GuardVerdict.REQUIRE_APPROVAL,
        guard_rule="decision_requires_approval",
        guard_reason="waiting on an analyst",
        engine_trust_tier=EngineTrustTier.DETERMINISTIC,
        decision_engine=decision.decision_engine,
        idempotency_key="k",
        response_duration_ms=1.0,
        audit=_AUDIT,
    )


def _state_with(**kwargs) -> PlatformStateModel:
    ctx = kwargs.pop("ctx", None) or CorrelationContext.create()
    state = create_initial_state(context=ctx)
    for key, value in kwargs.items():
        setattr(state, key, value)
    return state


def _memo_of(update) -> dict:
    return update["metadata"][COORDINATOR_METADATA_KEY]


# ── Routing order ─────────────────────────────────────────────────────────────


def test_empty_state_ends_immediately():
    agent = CoordinatorAgent()

    memo = _memo_of(agent(create_initial_state().to_graph_state()))

    assert memo["next_node"] == RouteTarget.END.value
    assert memo["status"] == "completed"
    assert memo["reason"] == "all pipeline work drained"


def test_undetected_event_routes_to_detection():
    ctx = CorrelationContext.create()
    state = _state_with(ctx=ctx, security_events=[_event(ctx)])

    memo = _memo_of(CoordinatorAgent()(state.to_graph_state()))

    assert memo["next_node"] == RouteTarget.DETECTION.value
    assert memo["pending"]["detection"] == 1


def test_unanalysed_detection_routes_to_analysis():
    ctx = CorrelationContext.create()
    event = _event(ctx)
    state = _state_with(
        ctx=ctx, security_events=[event], detection_results=[_detection(ctx, event)]
    )

    memo = _memo_of(CoordinatorAgent()(state.to_graph_state()))

    assert memo["next_node"] == RouteTarget.ANALYSIS.value


def test_undecided_analysis_routes_to_decision():
    ctx = CorrelationContext.create()
    event = _event(ctx)
    detection = _detection(ctx, event)
    state = _state_with(
        ctx=ctx,
        security_events=[event],
        detection_results=[detection],
        analysis_results=[_analysis(ctx, detection)],
    )

    memo = _memo_of(CoordinatorAgent()(state.to_graph_state()))

    assert memo["next_node"] == RouteTarget.DECISION.value


def test_unresponded_decision_routes_to_response():
    decision = make_decision()
    state = _state_with(decision_results=[decision])

    memo = _memo_of(CoordinatorAgent()(state.to_graph_state()))

    assert memo["next_node"] == RouteTarget.RESPONSE.value


def test_earlier_stage_wins_when_several_are_pending():
    """Breadth-first: every detection before any analysis."""
    ctx = CorrelationContext.create()
    event = _event(ctx)
    detection = _detection(ctx, event)
    state = _state_with(
        ctx=ctx,
        security_events=[event, _event(ctx, 1)],
        detection_results=[detection],
    )

    memo = _memo_of(CoordinatorAgent()(state.to_graph_state()))

    assert memo["next_node"] == RouteTarget.DETECTION.value


def test_coordinator_appends_to_no_result_list():
    """The coordinator routes; it must never produce domain records."""
    ctx = CorrelationContext.create()
    state = _state_with(ctx=ctx, security_events=[_event(ctx)])

    update = CoordinatorAgent()(state.to_graph_state())

    assert set(update) == {"correlation_id", "trace_id", "session_id", "metadata"}


def test_coordinator_preserves_other_agents_metadata():
    ctx = CorrelationContext.create()
    state = _state_with(ctx=ctx, metadata={"detection_agent": {"status": "completed"}})

    update = CoordinatorAgent()(state.to_graph_state())

    assert update["metadata"]["detection_agent"] == {"status": "completed"}


# ── Termination safety ────────────────────────────────────────────────────────


def test_stalled_stage_is_excluded_and_run_ends():
    """A stage that ran without producing output must not be redispatched.

    This is the live-lock guard: agents swallow their own exceptions and
    return without a result, leaving the item pending forever.
    """
    ctx = CorrelationContext.create()
    state = _state_with(ctx=ctx, security_events=[_event(ctx)])
    agent = CoordinatorAgent()

    first = agent(state.to_graph_state())
    assert _memo_of(first)["next_node"] == RouteTarget.DETECTION.value

    # Detection "ran" but produced nothing — replay the same state.
    state.metadata = first["metadata"]
    second = _memo_of(agent(state.to_graph_state()))

    assert second["next_node"] == RouteTarget.END.value
    assert "detection" in second["stalled_stages"]
    assert second["anomalies"]
    assert second["pending_total"] == 1, "the work is reported, not silently dropped"


def test_stall_in_one_stage_does_not_block_others():
    ctx = CorrelationContext.create()
    event = _event(ctx)
    detection = _detection(ctx, event)
    # An undetected second event plus an unanalysed detection.
    state = _state_with(
        ctx=ctx,
        security_events=[event, _event(ctx, 1)],
        detection_results=[detection],
    )
    agent = CoordinatorAgent()

    first = agent(state.to_graph_state())
    assert _memo_of(first)["next_node"] == RouteTarget.DETECTION.value

    state.metadata = first["metadata"]          # detection made no progress
    second = _memo_of(agent(state.to_graph_state()))

    assert "detection" in second["stalled_stages"]
    assert second["next_node"] == RouteTarget.ANALYSIS.value


def test_progress_clears_the_stall_check():
    ctx = CorrelationContext.create()
    event = _event(ctx)
    state = _state_with(ctx=ctx, security_events=[event, _event(ctx, 1)])
    agent = CoordinatorAgent()

    first = agent(state.to_graph_state())
    state.metadata = first["metadata"]
    state.detection_results = [_detection(ctx, event)]   # detection did work

    second = _memo_of(agent(state.to_graph_state()))

    assert second["stalled_stages"] == []
    assert second["next_node"] == RouteTarget.DETECTION.value


def test_iteration_budget_ends_the_run():
    ctx = CorrelationContext.create()
    state = _state_with(ctx=ctx, security_events=[_event(ctx)])
    agent = CoordinatorAgent(max_iterations=1)
    state.metadata = {COORDINATOR_METADATA_KEY: {"iteration": 1}}

    memo = _memo_of(agent(state.to_graph_state()))

    assert memo["next_node"] == RouteTarget.END.value
    assert "budget" in memo["reason"]


def test_max_iterations_must_be_positive():
    with pytest.raises(ValueError):
        CoordinatorAgent(max_iterations=0)


def test_state_carries_all_bookkeeping_not_the_instance():
    """Agents are module-level singletons; counters on self would leak."""
    ctx = CorrelationContext.create()
    agent = CoordinatorAgent()

    run_one = _memo_of(agent(_state_with(ctx=ctx, security_events=[_event(ctx)]).to_graph_state()))
    run_two = _memo_of(agent(_state_with(security_events=[]).to_graph_state()))

    assert run_one["iteration"] == 1
    assert run_two["iteration"] == 0, "a fresh run must start from zero"
    assert not hasattr(agent, "iteration")


def test_coordinator_failure_ends_the_run_rather_than_hanging():
    agent = CoordinatorAgent()

    update = agent({"correlation_id": "not-a-uuid"})

    assert update["errors"]
    assert update["metadata"][COORDINATOR_METADATA_KEY]["next_node"] == RouteTarget.END.value
    assert agent.route(update) == RouteTarget.END.value


# ── Approval resume ───────────────────────────────────────────────────────────


def test_decision_awaiting_approval_is_routed_for_resume():
    decision = make_decision(
        requires_approval=True, approval_status=ApprovalStatus.PENDING
    )
    state = _state_with(
        decision_results=[decision], response_results=[_awaiting_response(decision)]
    )

    memo = _memo_of(CoordinatorAgent()(state.to_graph_state()))

    assert memo["next_node"] == RouteTarget.RESPONSE.value
    assert "resume" in memo["reason"]


def test_resume_is_attempted_at_most_once_per_run():
    """An approval that never arrives must not be retried forever."""
    decision = make_decision(
        requires_approval=True, approval_status=ApprovalStatus.PENDING
    )
    state = _state_with(
        decision_results=[decision], response_results=[_awaiting_response(decision)]
    )
    agent = CoordinatorAgent()

    first = agent(state.to_graph_state())
    assert _memo_of(first)["next_node"] == RouteTarget.RESPONSE.value

    # Response ran again and produced another AWAITING_APPROVAL.
    state.metadata = first["metadata"]
    state.response_results = [*state.response_results, _awaiting_response(decision)]
    second = _memo_of(agent(state.to_graph_state()))

    assert second["next_node"] == RouteTarget.END.value
    assert decision.decision_id in second["resume_attempted"]


def test_terminal_response_is_not_resumed():
    decision = make_decision()
    executed = _awaiting_response(decision).model_copy(
        update={
            "status": ResponseStatus.NO_OP,
            "guard_verdict": GuardVerdict.ALLOW,
            "guard_rule": "authorised",
        }
    )
    state = _state_with(decision_results=[decision], response_results=[executed])

    memo = _memo_of(CoordinatorAgent()(state.to_graph_state()))

    assert memo["next_node"] == RouteTarget.END.value


# ── Deduplication ─────────────────────────────────────────────────────────────


def test_exact_duplicate_event_ids_are_suppressed():
    ctx = CorrelationContext.create()
    event = _event(ctx)
    state = _state_with(ctx=ctx, security_events=[event, event])

    memo = _memo_of(CoordinatorAgent()(state.to_graph_state()))

    assert memo["suppressed_event_ids"] == [event.event_id]
    assert memo["pending"]["detection"] == 0
    assert memo["next_node"] == RouteTarget.END.value


def test_identical_flow_content_is_not_deduplicated():
    """Repeated identical flows are the signal an IDS exists to catch."""
    ctx = CorrelationContext.create()
    first, second = _event(ctx, 0), _event(ctx, 0)    # same content, distinct IDs
    state = _state_with(ctx=ctx, security_events=[first, second])

    assert find_duplicate_event_ids(state) == ()
    memo = _memo_of(CoordinatorAgent()(state.to_graph_state()))
    assert memo["pending"]["detection"] == 2


# ── Pure routing functions ────────────────────────────────────────────────────


def test_work_queue_counts_every_stage():
    ctx = CorrelationContext.create()
    event = _event(ctx)
    detection = _detection(ctx, event)
    state = _state_with(
        ctx=ctx,
        security_events=[event, _event(ctx, 1)],
        detection_results=[detection],
        analysis_results=[_analysis(ctx, detection)],
        decision_results=[make_decision()],
    )

    queue = build_work_queue(state)

    # The lone analysis has no matching decision (make_decision() invents its
    # own analysis_id), so the decision stage is pending too.
    assert queue.as_counts() == {
        "detection": 1, "analysis": 0, "decision": 1,
        "response": 1, "response_resumable": 0,
    }
    assert queue.total == 3


def test_decide_route_is_pure_and_repeatable():
    ctx = CorrelationContext.create()
    state = _state_with(ctx=ctx, security_events=[_event(ctx)])
    memo = CoordinatorMemo()

    first, _ = decide_route(state, memo, max_iterations=10)
    second, _ = decide_route(state, memo, max_iterations=10)

    assert first == second
    assert memo.iteration == 0, "decide_route must not mutate the memo"


def test_route_reads_the_recorded_decision():
    ctx = CorrelationContext.create()
    agent = CoordinatorAgent()
    state = _state_with(ctx=ctx, security_events=[_event(ctx)])

    update = agent(state.to_graph_state())

    assert agent.route(update) == RouteTarget.DETECTION.value


def test_route_rederives_when_metadata_is_missing():
    ctx = CorrelationContext.create()
    agent = CoordinatorAgent()
    state = _state_with(ctx=ctx, security_events=[_event(ctx)])

    assert agent.route(state.to_graph_state()) == RouteTarget.DETECTION.value
