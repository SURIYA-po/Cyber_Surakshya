"""Graph-level tests for coordinated execution.

These use lightweight stub agents that mimic the real ones — each processes
exactly ONE pending item per invocation — so the tests exercise the routing
loop without loading the ML stack.
"""
from __future__ import annotations

import pytest

from agents.coordinator.coordinator_agent import CoordinatorAgent
from agents.coordinator.routing import COORDINATOR_METADATA_KEY
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
from cyber_surakshya.platform.schemas.detection_result import DetectionResult
from cyber_surakshya.platform.schemas.security_event import (
    NetworkEndpoint,
    SecurityEvent,
)
from cyber_surakshya.platform.state import (
    PlatformSharedState,
    PlatformStateModel,
    create_initial_state,
)
from graph.builder import GraphBuilder
from graph.config import GraphConfig
from graph.runtime import GraphRuntime

_AUDIT = AuditMetadata(created_by="t", updated_by="t", source_system="t")


# ── Stub agents: one pending item per invocation, like the real ones ──────────


def _stub_detection(state: PlatformSharedState) -> PlatformSharedState:
    model = PlatformStateModel.from_graph_state(state)
    done = {d.event_id for d in model.detection_results}
    for event in model.security_events:
        if event.event_id in done:
            continue
        return PlatformSharedState(
            detection_results=[
                DetectionResult(
                    detection_id=generate_detection_id(),
                    event_id=event.event_id,
                    correlation_id=model.correlation_id,
                    trace_id=model.trace_id,
                    status=DetectionStatus.DETECTED,
                    severity=Severity.HIGH,
                    risk_score=RiskScore(value=70.0),
                    model_name="stub",
                    model_version="1.0.0",
                    predicted_label="DDOS",
                    confidence=0.9,
                    audit=_AUDIT,
                )
            ]
        )
    return PlatformSharedState(metadata={**model.metadata, "detection": "idle"})


def _stub_analysis(state: PlatformSharedState) -> PlatformSharedState:
    model = PlatformStateModel.from_graph_state(state)
    done = {a.detection_id for a in model.analysis_results}
    for detection in model.detection_results:
        if detection.detection_id in done:
            continue
        return PlatformSharedState(
            analysis_results=[
                AnalysisResult(
                    analysis_id=generate_analysis_id(),
                    event_id=detection.event_id,
                    detection_id=detection.detection_id,
                    correlation_id=model.correlation_id,
                    trace_id=model.trace_id,
                    severity=Severity.HIGH,
                    risk_score=RiskScore(value=70.0),
                    summary="stub summary",
                    reasoning="stub reasoning",
                    confidence=0.9,
                    audit=_AUDIT,
                )
            ]
        )
    return PlatformSharedState(metadata={**model.metadata, "analysis": "idle"})


def _broken_detection(state: PlatformSharedState) -> PlatformSharedState:
    """Mimics an agent that swallows its exception and produces nothing."""
    model = PlatformStateModel.from_graph_state(state)
    return PlatformSharedState(
        errors=["detection_agent: simulated failure"],
        metadata={**model.metadata},
    )


def _make_events(ctx: CorrelationContext, count: int) -> list[SecurityEvent]:
    return [
        SecurityEvent(
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
        for index in range(count)
    ]


def _coordinated_runtime(
    *,
    detection=_stub_detection,
    analysis=_stub_analysis,
    max_iterations: int = 100,
) -> GraphRuntime:
    builder = GraphBuilder()
    builder.register_node("detection", detection)
    builder.register_node("analysis", analysis)
    # This graph registers only two of the four pipeline stages, so the
    # coordinator must be told what exists — otherwise it would route to
    # "decision" and LangGraph would raise a bare KeyError mid-run.
    coordinator = CoordinatorAgent(
        max_iterations=max_iterations, stages=["detection", "analysis"]
    )
    builder.register_coordinator(
        "coordinator",
        coordinator,
        coordinator.route,
        routable_targets=coordinator.routable_targets,
    )
    return GraphRuntime(builder=builder)


# ── The regression this component exists to prevent ───────────────────────────


@pytest.mark.parametrize("event_count", [1, 3, 5])
def test_every_event_traverses_the_full_pipeline(event_count):
    """Before the coordinator, N events in produced exactly 1 of each output."""
    ctx = CorrelationContext.create()
    state = create_initial_state(context=ctx)
    state.security_events = _make_events(ctx, event_count)

    result = _coordinated_runtime().execute(state)

    assert len(result.detection_results) == event_count
    assert len(result.analysis_results) == event_count


def test_linear_graph_still_drops_work_without_a_coordinator():
    """Pins why the coordinator is required, not merely convenient."""
    ctx = CorrelationContext.create()
    state = create_initial_state(context=ctx)
    state.security_events = _make_events(ctx, 3)

    builder = GraphBuilder()
    builder.register_node("detection", _stub_detection)
    builder.register_node("analysis", _stub_analysis)
    result = GraphRuntime(builder=builder).execute(state)

    assert len(result.detection_results) == 1
    assert len(result.analysis_results) == 1


def test_run_summary_reports_dispatches_and_drain():
    ctx = CorrelationContext.create()
    state = create_initial_state(context=ctx)
    state.security_events = _make_events(ctx, 3)

    result = _coordinated_runtime().execute(state)

    memo = result.metadata[COORDINATOR_METADATA_KEY]
    assert memo["status"] == "completed"
    assert memo["dispatches"] == {"detection": 3, "analysis": 3}
    assert memo["stalled_stages"] == []
    # Both registered stages drained.
    assert memo["pending"]["detection"] == 0
    assert memo["pending"]["analysis"] == 0
    # Pending totals are absolute, not filtered to the stages this graph has:
    # a partial pipeline reports the work it cannot do rather than hiding it.
    assert memo["pending"]["decision"] == 3


# ── Termination safety ────────────────────────────────────────────────────────


def test_failing_agent_stalls_its_stage_instead_of_hanging():
    """A live-lock would hang the suite; a stall ends the run with a report."""
    ctx = CorrelationContext.create()
    state = create_initial_state(context=ctx)
    state.security_events = _make_events(ctx, 3)

    result = _coordinated_runtime(detection=_broken_detection).execute(state)

    memo = result.metadata[COORDINATOR_METADATA_KEY]
    assert result.detection_results == []
    assert "detection" in memo["stalled_stages"]
    assert memo["pending_total"] == 3, "dropped work is reported, not hidden"
    assert result.errors


def test_iteration_budget_bounds_a_pathological_run():
    ctx = CorrelationContext.create()
    state = create_initial_state(context=ctx)
    state.security_events = _make_events(ctx, 5)

    result = _coordinated_runtime(max_iterations=2).execute(state)

    memo = result.metadata[COORDINATOR_METADATA_KEY]
    assert memo["iteration"] == 2
    assert "budget" in memo["reason"]
    assert len(result.detection_results) == 2


# ── Builder contract ──────────────────────────────────────────────────────────


def test_builder_defaults_to_linear_mode():
    builder = GraphBuilder()
    builder.register_node("only", _stub_detection)

    assert builder.is_coordinated is False


def test_registering_a_coordinator_switches_mode():
    builder = GraphBuilder()
    builder.register_node("detection", _stub_detection)
    coordinator = CoordinatorAgent()
    builder.register_coordinator("coordinator", coordinator, coordinator.route)

    assert builder.is_coordinated is True


def test_coordinated_graph_requires_worker_nodes():
    builder = GraphBuilder()
    coordinator = CoordinatorAgent()
    builder.register_coordinator("coordinator", coordinator, coordinator.route)

    with pytest.raises(ValueError, match="at least one worker node"):
        builder.compile()


def test_duplicate_coordinator_registration_is_rejected():
    builder = GraphBuilder()
    coordinator = CoordinatorAgent()
    builder.register_coordinator("coordinator", coordinator, coordinator.route)

    with pytest.raises(ValueError, match="already registered"):
        builder.register_coordinator("other", coordinator, coordinator.route)


def test_worker_node_cannot_collide_with_the_coordinator():
    builder = GraphBuilder()
    coordinator = CoordinatorAgent()
    builder.register_coordinator("coordinator", coordinator, coordinator.route)

    with pytest.raises(ValueError, match="collides"):
        builder.register_node("coordinator", _stub_detection)


# ── Recursion limit ───────────────────────────────────────────────────────────


def test_recursion_limit_is_derived_in_coordinated_mode():
    """The default of 25 would abort a three-event run mid-pipeline."""
    config = GraphConfig(coordinator_max_iterations=100)

    assert config.effective_recursion_limit(coordinated=False) == 25
    assert config.effective_recursion_limit(coordinated=True) == 204


def test_explicit_recursion_limit_wins_when_larger():
    config = GraphConfig(recursion_limit=500, coordinator_max_iterations=10)

    assert config.effective_recursion_limit(coordinated=True) == 500
