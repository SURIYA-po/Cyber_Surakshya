"""Tests for the Analysis Agent."""

from __future__ import annotations

from adapters.detection.ids_adapter import IDSDetectionAdapter
from agents.analysis import AnalysisAgent
from agents.decision.decision_agent import DecisionAgent
from agents.decision.deterministic import DeterministicDecisionEngine
from agents.detection import DetectionAgent
from ai_engine import AnalysisContext
from ai_engine.deterministic import DeterministicRuleEngine
from cyber_surakshya.platform.audit.metadata import AuditMetadata
from cyber_surakshya.platform.enums.detection_status import DetectionStatus
from cyber_surakshya.platform.enums.severity import Severity
from cyber_surakshya.platform.identifiers.correlation import (
    CorrelationContext,
    generate_correlation_id,
    generate_event_id,
    generate_trace_id,
)
from cyber_surakshya.platform.risk.score import RiskScore
from cyber_surakshya.platform.schemas.detection_result import DetectionResult
from cyber_surakshya.platform.state import create_initial_state
from graph.builder import GraphBuilder
from graph.checkpointing import InMemoryStatePersistence
from graph.runtime import GraphRuntime
from memory.inmemory import InMemoryMemoryProvider
from memory.models import MemoryQuery
from tests.platform.conftest import sample_detection_result, sample_security_event


class FakeIDSDetectionAdapter(IDSDetectionAdapter):
    def detect(self, flow_data: dict[str, object]) -> DetectionResult:
        return DetectionResult(
            event_id=generate_event_id(),
            correlation_id=generate_correlation_id(),
            trace_id=generate_trace_id(),
            status=DetectionStatus.DETECTED,
            severity=Severity.CRITICAL,
            risk_score=RiskScore(value=96.0),
            model_name="FakeIDS",
            model_version="test",
            predicted_label="DDoS",
            confidence=0.96,
            probabilities={"BENIGN": 0.04, "DDoS": 0.96},
            is_anomaly=True,
            feature_snapshot={"Flow Packets/s": 20000.0},
            audit=AuditMetadata(
                created_by="fake_ids",
                updated_by="fake_ids",
                source_system="ids",
            ),
        )


def test_analysis_agent_analyzes_first_pending_detection():
    context = CorrelationContext.create()
    event = sample_security_event(context)
    detection = sample_detection_result(event)
    state = create_initial_state(context).model_copy(
        update={
            "security_events": [event],
            "detection_results": [detection],
        }
    )
    agent = AnalysisAgent(DeterministicRuleEngine())

    update = agent(state.to_graph_state())

    assert len(update["analysis_results"]) == 1
    analysis = update["analysis_results"][0]
    assert analysis.event_id == event.event_id
    assert analysis.detection_id == detection.detection_id
    assert analysis.correlation_id == state.correlation_id
    assert analysis.trace_id == state.trace_id
    assert update["metadata"]["analysis_agent"]["status"] == "completed"


def test_analysis_agent_skips_already_analyzed_detection():
    context = CorrelationContext.create()
    event = sample_security_event(context)
    detection = sample_detection_result(event)
    existing_analysis = DeterministicRuleEngine().analyze(
        AnalysisContext(
            security_event=event,
            detection_result=detection,
        )
    )
    state = create_initial_state(context).model_copy(
        update={
            "security_events": [event],
            "detection_results": [detection],
            "analysis_results": [existing_analysis],
        }
    )
    agent = AnalysisAgent(DeterministicRuleEngine())

    update = agent(state.to_graph_state())

    assert "analysis_results" not in update
    assert update["metadata"]["analysis_agent"]["status"] == "skipped"


def test_analysis_agent_returns_error_when_source_event_is_missing():
    event = sample_security_event()
    detection = sample_detection_result(event)
    state = create_initial_state().model_copy(
        update={"detection_results": [detection]}
    )
    agent = AnalysisAgent(DeterministicRuleEngine())

    update = agent(state.to_graph_state())

    assert "analysis_results" not in update
    assert "No SecurityEvent found" in update["errors"][0]
    assert update["metadata"]["analysis_agent"]["status"] == "failed"


def test_detection_then_analysis_runs_inside_langgraph_runtime():
    context = CorrelationContext.create()
    event = sample_security_event(context)
    initial_state = create_initial_state(context).model_copy(
        update={"security_events": [event]}
    )
    builder = GraphBuilder()
    builder.register_node("detection", DetectionAgent(FakeIDSDetectionAdapter()))
    builder.register_node("analysis", AnalysisAgent(DeterministicRuleEngine()))
    persistence = InMemoryStatePersistence()
    runtime = GraphRuntime(builder=builder, persistence=persistence)

    result = runtime.execute(initial_state, run_id="analysis-run")

    assert len(result.security_events) == 1
    assert len(result.detection_results) == 1
    assert len(result.analysis_results) == 1
    assert result.analysis_results[0].detection_id == result.detection_results[0].detection_id
    assert result.metadata["analysis_agent"]["status"] == "completed"
    assert persistence.load("analysis-run") == result


def test_shared_memory_provider_is_used_across_agents():
    context = CorrelationContext.create()
    event = sample_security_event(context)
    initial_state = create_initial_state(context).model_copy(
        update={"security_events": [event]}
    )
    provider = InMemoryMemoryProvider()

    builder = GraphBuilder()
    builder.register_node(
        "detection",
        DetectionAgent(FakeIDSDetectionAdapter(), memory_provider=provider),
    )
    builder.register_node(
        "analysis",
        AnalysisAgent(DeterministicRuleEngine(), memory_provider=provider),
    )
    builder.register_node(
        "decision",
        DecisionAgent(DeterministicDecisionEngine(), memory_provider=provider),
    )
    runtime = GraphRuntime(builder=builder, persistence=InMemoryStatePersistence())

    result = runtime.execute(initial_state, run_id="shared-memory-run")

    detection_records = provider.search(
        "detections",
        MemoryQuery(record_types=["detection_result"], limit=10),
    )
    analysis_records = provider.search(
        "analysis",
        MemoryQuery(record_types=["analysis_result"], limit=10),
    )
    decision_records = provider.search(
        "decisions",
        MemoryQuery(record_types=["decision_result"], limit=10),
    )

    assert len(detection_records) == 1
    assert len(analysis_records) == 1
    assert len(decision_records) == 1
    assert len(result.decision_results) == 1
