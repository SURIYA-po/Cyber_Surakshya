"""Tests for the Detection Agent."""

from __future__ import annotations

from typing import Any

from adapters.detection.ids_adapter import IDSDetectionAdapter
from agents.detection import DetectionAgent
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
from tests.platform.conftest import sample_security_event


class FakeIDSDetectionAdapter(IDSDetectionAdapter):
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def detect(self, flow_data: dict[str, Any]) -> DetectionResult:
        self.calls.append(flow_data)
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
            feature_snapshot={
                key: float(value)
                for key, value in flow_data.items()
                if isinstance(value, int | float)
            },
            audit=AuditMetadata(
                created_by="fake_ids",
                updated_by="fake_ids",
                source_system="ids",
            ),
        )


def test_detection_agent_extracts_features_and_returns_detection_update():
    context = CorrelationContext.create()
    event = sample_security_event(context)
    state = create_initial_state(context).model_copy(
        update={"security_events": [event]}
    )
    adapter = FakeIDSDetectionAdapter()
    agent = DetectionAgent(adapter)

    update = agent(state.to_graph_state())

    assert adapter.calls == [event.features]
    assert len(update["detection_results"]) == 1
    detection = update["detection_results"][0]
    assert detection.event_id == event.event_id
    assert detection.correlation_id == state.correlation_id
    assert detection.trace_id == state.trace_id
    assert update["metadata"]["detection_agent"]["status"] == "completed"
    assert update["metadata"]["detection_agent"]["last_detection_id"]


def test_detection_agent_falls_back_to_raw_payload_when_features_are_empty():
    context = CorrelationContext.create()
    event = sample_security_event(context).model_copy(
        update={
            "features": {},
            "raw_payload": {
                "Destination Port": 443,
                "Flow Packets/s": 42.0,
            },
        }
    )
    state = create_initial_state(context).model_copy(
        update={"security_events": [event]}
    )
    adapter = FakeIDSDetectionAdapter()
    agent = DetectionAgent(adapter)

    update = agent(state.to_graph_state())

    assert adapter.calls == [event.raw_payload]
    assert update["detection_results"][0].event_id == event.event_id


def test_detection_agent_returns_error_update_when_flow_data_is_missing():
    context = CorrelationContext.create()
    event = sample_security_event(context).model_copy(
        update={"features": {}, "raw_payload": {}}
    )
    state = create_initial_state(context).model_copy(
        update={"security_events": [event]}
    )
    adapter = FakeIDSDetectionAdapter()
    agent = DetectionAgent(adapter)

    update = agent(state.to_graph_state())

    assert adapter.calls == []
    assert "has no features or raw_payload" in update["errors"][0]
    assert update["metadata"]["detection_agent"]["status"] == "failed"


def test_detection_agent_skips_when_no_pending_security_events():
    context = CorrelationContext.create()
    event = sample_security_event(context)
    detection = FakeIDSDetectionAdapter().detect(event.features).model_copy(
        update={
            "event_id": event.event_id,
            "correlation_id": context.correlation_id,
            "trace_id": context.trace_id,
        }
    )
    state = create_initial_state(context).model_copy(
        update={
            "security_events": [event],
            "detection_results": [detection],
        }
    )
    adapter = FakeIDSDetectionAdapter()
    agent = DetectionAgent(adapter)

    update = agent(state.to_graph_state())

    assert adapter.calls == []
    assert "detection_results" not in update
    assert update["metadata"]["detection_agent"]["status"] == "skipped"


def test_detection_agent_runs_inside_langgraph_runtime_and_persists_state():
    context = CorrelationContext.create()
    event = sample_security_event(context)
    initial_state = create_initial_state(context).model_copy(
        update={"security_events": [event]}
    )
    adapter = FakeIDSDetectionAdapter()
    builder = GraphBuilder()
    builder.register_node("detection", DetectionAgent(adapter))
    persistence = InMemoryStatePersistence()
    runtime = GraphRuntime(builder=builder, persistence=persistence)

    result = runtime.execute(initial_state, run_id="detection-run")

    assert adapter.calls == [event.features]
    assert len(result.security_events) == 1
    assert len(result.detection_results) == 1
    assert result.detection_results[0].event_id == event.event_id
    assert result.metadata["detection_agent"]["status"] == "completed"
    assert persistence.load("detection-run") == result
