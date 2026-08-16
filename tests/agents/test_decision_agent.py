"""Unit and integration tests for DecisionAgent and DecisionResult schema."""

from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from agents.decision.decision_agent import DecisionAgent
from agents.decision.deterministic import DeterministicDecisionEngine
from cyber_surakshya.platform.actions.action_type import ActionType
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
from cyber_surakshya.platform.schemas.decision_result import (
    ApprovalStatus,
    DecisionPriority,
    DecisionResult,
    DecisionStatus,
)
from cyber_surakshya.platform.schemas.detection_result import DetectionResult
from cyber_surakshya.platform.schemas.security_event import NetworkEndpoint, SecurityEvent
from cyber_surakshya.platform.state import create_initial_state
from memory.models import MemoryRecord, MemorySearchResult


def _create_sample_harness(
    severity: Severity = Severity.CRITICAL,
    risk_score_val: float = 90.0,
    status: DetectionStatus = DetectionStatus.DETECTED,
    confidence: float = 0.9,
    predicted_label: str = "DDoS",
):
    ctx = CorrelationContext.create()
    state = create_initial_state(context=ctx)

    event_id = generate_event_id()
    det_id = generate_detection_id()
    ana_id = generate_analysis_id()

    event = SecurityEvent(
        event_id=event_id,
        correlation_id=ctx.correlation_id,
        trace_id=ctx.trace_id,
        event_type=EventType.NETWORK_FLOW,
        source=EventSource.IDS,
        severity=severity,
        risk_score=RiskScore(value=risk_score_val),
        title="Test Event",
        network=NetworkEndpoint(
            source_ip="192.168.1.50",
            destination_ip="10.0.0.1",
            destination_port=80,
        ),
        audit=AuditMetadata(
            created_by="test", updated_by="test", source_system="test"
        ),
    )

    detection = DetectionResult(
        detection_id=det_id,
        event_id=event_id,
        correlation_id=ctx.correlation_id,
        trace_id=ctx.trace_id,
        status=status,
        severity=severity,
        risk_score=RiskScore(value=risk_score_val),
        model_name="test_model",
        model_version="1.0.0",
        predicted_label=predicted_label if status == DetectionStatus.DETECTED else "BENIGN",
        confidence=confidence,
        audit=AuditMetadata(
            created_by="test", updated_by="test", source_system="test"
        ),
    )

    analysis = AnalysisResult(
        analysis_id=ana_id,
        event_id=event_id,
        detection_id=det_id,
        correlation_id=ctx.correlation_id,
        trace_id=ctx.trace_id,
        severity=severity,
        risk_score=RiskScore(value=risk_score_val),
        summary="Test Analysis Summary",
        reasoning="Test Reasoning",
        confidence=confidence,
        audit=AuditMetadata(
            created_by="test", updated_by="test", source_system="test"
        ),
    )

    state.security_events.append(event)
    state.detection_results.append(detection)
    state.analysis_results.append(analysis)

    return state, event, detection, analysis


def test_critical_risk_produces_block_ip():
    state, _, _, _ = _create_sample_harness(
        severity=Severity.CRITICAL, risk_score_val=90.0
    )
    agent = DecisionAgent(decision_engine=DeterministicDecisionEngine())
    res_state = agent(state.to_graph_state())

    assert len(res_state["decision_results"]) == 1
    decision: DecisionResult = res_state["decision_results"][0]

    assert decision.action.action_type == ActionType.BLOCK_IP
    assert decision.action.target.target_value == "192.168.1.50"
    assert decision.priority == DecisionPriority.CRITICAL
    assert decision.requires_approval is False
    assert decision.approval_status == ApprovalStatus.AUTO_APPROVED
    assert decision.status == DecisionStatus.READY_FOR_EXECUTION


def test_low_severity_detection_is_reported_not_contained():
    """A low-consequence detection must still produce a decision.

    Risk now reflects attack class rather than classifier confidence, so
    reconnaissance scores around 40 and a low-confidence one lands under the
    MEDIUM floor of the rate-limit rule. Before the catch-all rule existed,
    such a detection matched nothing and make_decision raised
    PolicyEvaluationError — a detected attack crashed the pipeline.
    """
    state, _, _, _ = _create_sample_harness(
        severity=Severity.LOW,
        risk_score_val=24.0,
        status=DetectionStatus.DETECTED,
        confidence=0.6,
        predicted_label="PORTSCAN",
    )
    agent = DecisionAgent(decision_engine=DeterministicDecisionEngine())
    res_state = agent(state.to_graph_state())

    assert len(res_state["decision_results"]) == 1
    decision: DecisionResult = res_state["decision_results"][0]

    assert decision.policy_name == "low_severity_detected_notify"
    assert decision.action.action_type == ActionType.NOTIFY_SOC
    assert decision.priority == DecisionPriority.LOW
    assert decision.requires_approval is False


def test_benign_flow_from_repeat_offender_is_not_isolated():
    """Prior incidents alone are not evidence of current malicious activity.

    The repeat-offender rule carried no detection-status condition, so a
    BENIGN flow from an IP with two prior records proposed isolating the host.
    """
    state, _, _, _ = _create_sample_harness(
        severity=Severity.INFO,
        risk_score_val=0.0,
        status=DetectionStatus.BENIGN,
        confidence=0.99,
    )
    mock_memory = MagicMock()
    mock_memory.search.return_value = [
        MemorySearchResult(
            record=MemoryRecord(
                record_type="threat_event",
                entity_id="192.168.1.50",
                content={"event": "prior attack"},
            ),
            score=1.0,
        )
        for _ in range(3)
    ]

    agent = DecisionAgent(
        decision_engine=DeterministicDecisionEngine(),
        memory_provider=mock_memory,
    )
    res_state = agent(state.to_graph_state())

    decision: DecisionResult = res_state["decision_results"][0]
    assert decision.action.action_type == ActionType.LOG_ONLY
    assert decision.policy_name == "benign_log_only"


def test_repeat_offender_produces_isolate():
    state, _, _, _ = _create_sample_harness(
        severity=Severity.MEDIUM, risk_score_val=50.0
    )
    mock_memory = MagicMock()
    mock_record = MemoryRecord(
        record_type="threat_event",
        entity_id="192.168.1.50",
        content={"event": "prior attack"},
    )
    mock_memory.search.return_value = [
        MemorySearchResult(record=mock_record),
        MemorySearchResult(record=mock_record),
    ]

    agent = DecisionAgent(
        decision_engine=DeterministicDecisionEngine(), memory_provider=mock_memory
    )
    res_state = agent(state.to_graph_state())

    decision: DecisionResult = res_state["decision_results"][0]
    assert decision.action.action_type == ActionType.ISOLATE_HOST
    assert decision.priority == DecisionPriority.CRITICAL
    assert decision.requires_approval is True
    assert decision.approval_status == ApprovalStatus.PENDING
    assert decision.status == DecisionStatus.WAITING_APPROVAL
    assert decision.memory_hits == 2


def test_high_confidence_detected_produces_notify():
    state, _, _, _ = _create_sample_harness(
        severity=Severity.HIGH, risk_score_val=70.0, confidence=0.85
    )
    agent = DecisionAgent(decision_engine=DeterministicDecisionEngine())
    res_state = agent(state.to_graph_state())

    decision: DecisionResult = res_state["decision_results"][0]
    assert decision.action.action_type == ActionType.NOTIFY_SOC
    assert decision.priority == DecisionPriority.HIGH
    assert decision.requires_approval is False
    assert decision.approval_status == ApprovalStatus.AUTO_APPROVED


def test_inconclusive_produces_notify_medium():
    state, _, _, _ = _create_sample_harness(
        severity=Severity.MEDIUM,
        risk_score_val=40.0,
        status=DetectionStatus.INCONCLUSIVE,
    )
    agent = DecisionAgent(decision_engine=DeterministicDecisionEngine())
    res_state = agent(state.to_graph_state())

    decision: DecisionResult = res_state["decision_results"][0]
    assert decision.action.action_type == ActionType.NOTIFY_SOC
    assert decision.priority == DecisionPriority.MEDIUM
    assert decision.status == DecisionStatus.READY_FOR_EXECUTION


def test_benign_produces_log_only():
    state, _, _, _ = _create_sample_harness(
        severity=Severity.INFO,
        risk_score_val=5.0,
        status=DetectionStatus.BENIGN,
        predicted_label="BENIGN",
    )
    agent = DecisionAgent(decision_engine=DeterministicDecisionEngine())
    res_state = agent(state.to_graph_state())

    decision: DecisionResult = res_state["decision_results"][0]
    assert decision.action.action_type == ActionType.LOG_ONLY
    assert decision.priority == DecisionPriority.LOW
    assert decision.requires_approval is False


def test_decision_result_correlation_ids_match():
    state, _, _, _ = _create_sample_harness()
    agent = DecisionAgent(decision_engine=DeterministicDecisionEngine())
    res_state = agent(state.to_graph_state())

    decision: DecisionResult = res_state["decision_results"][0]
    assert decision.correlation_id == state.correlation_id
    assert decision.trace_id == state.trace_id


def test_no_pending_analysis_skips_gracefully():
    ctx = CorrelationContext.create()
    state = create_initial_state(context=ctx)
    agent = DecisionAgent(decision_engine=DeterministicDecisionEngine())
    res_state = agent(state.to_graph_state())

    assert "decision_results" not in res_state or len(res_state.get("decision_results", [])) == 0
    assert res_state["metadata"]["decision_agent"]["status"] == "skipped"


def test_approval_lifecycle_validation():
    with pytest.raises(ValidationError):
        # Invalid combination: requires_approval=True with AUTO_APPROVED
        state, _, _, ana = _create_sample_harness()
        agent = DecisionAgent(decision_engine=DeterministicDecisionEngine())
        res_state = agent(state.to_graph_state())
        DecisionResult(
            analysis_id=ana.analysis_id,
            detection_id=ana.detection_id,
            event_id=ana.event_id,
            correlation_id=ana.correlation_id,
            trace_id=ana.trace_id,
            action=res_state["decision_results"][0].action,
            priority=DecisionPriority.CRITICAL,
            requires_approval=True,
            approval_status=ApprovalStatus.AUTO_APPROVED,  # Invalid!
            rationale="Test Invalid",
            confidence=0.9,
            policy_version="1.0.0",
            decision_engine="TestEngine",
            engine_version="1.0.0",
            policy_name="test_policy",
            decision_duration_ms=1.5,
            memory_hits=0,
            audit=AuditMetadata(
                created_by="test", updated_by="test", source_system="test"
            ),
        )


def test_decision_result_versioning_fields():
    state, _, _, _ = _create_sample_harness()
    agent = DecisionAgent(decision_engine=DeterministicDecisionEngine())
    res_state = agent(state.to_graph_state())

    decision: DecisionResult = res_state["decision_results"][0]
    assert decision.policy_version == "1.0.0"
    assert decision.decision_engine == "DeterministicDecisionEngine"
    assert decision.engine_version == "1.0.0"
    assert len(decision.policy_name) > 0


def test_decision_duration_ms_recorded():
    state, _, _, _ = _create_sample_harness()
    agent = DecisionAgent(decision_engine=DeterministicDecisionEngine())
    res_state = agent(state.to_graph_state())

    decision: DecisionResult = res_state["decision_results"][0]
    assert decision.decision_duration_ms >= 0.0


def _real_attack_profile(label: str = "DDOS") -> dict[str, float]:
    """Load a complete 42-feature median vector for one class.

    The end-to-end test used to hand the real model three features
    ({Destination Port, Flow Duration, Total Fwd Packets}), leaving 39
    zero-filled. That is not an end-to-end test of detection — it is a test
    that the pipeline does not crash on a fabricated vector. The adapter now
    refuses such input, so the test uses a real profile.
    """
    import json
    from pathlib import Path

    path = Path(__file__).resolve().parents[2] / "artifacts" / "attack_profiles.json"
    if not path.exists():
        pytest.skip(
            "artifacts/attack_profiles.json missing; generate it with "
            "python scripts/build_attack_profiles.py"
        )
    profiles = json.loads(path.read_text(encoding="utf-8"))["profiles"]
    if label not in profiles:
        pytest.skip(f"profile {label!r} not present in attack_profiles.json")
    return profiles[label]


def test_end_to_end_graph_pipeline():
    from adapters.detection.ids_adapter import IDSDetectionAdapter
    from agents.analysis.analysis_agent import AnalysisAgent
    from agents.detection.detection_agent import DetectionAgent
    from ai_engine.deterministic import DeterministicRuleEngine
    from graph.builder import GraphBuilder
    from graph.runtime import GraphRuntime
    from inference import ArtifactError

    features = _real_attack_profile("DDOS")

    try:
        adapter = IDSDetectionAdapter()
        adapter._get_artifacts()
    except ArtifactError as exc:
        pytest.skip(f"IDS artifacts unavailable: {exc}")
    builder = GraphBuilder()
    builder.register_node("detection", DetectionAgent(adapter))
    builder.register_node("analysis", AnalysisAgent(DeterministicRuleEngine()))
    builder.register_node("decision", DecisionAgent(DeterministicDecisionEngine()))

    runtime = GraphRuntime(builder=builder)

    ctx = CorrelationContext.create()
    state = create_initial_state(context=ctx)
    event = SecurityEvent(
        correlation_id=ctx.correlation_id,
        trace_id=ctx.trace_id,
        event_type=EventType.NETWORK_FLOW,
        source=EventSource.IDS,
        severity=Severity.INFO,
        risk_score=RiskScore(value=0.0),
        title="Simulated Flow",
        network=NetworkEndpoint(source_ip="192.168.1.100", destination_ip="10.0.0.1", destination_port=80),
        features=features,
        audit=AuditMetadata(created_by="sim", updated_by="sim", source_system="test")
    )
    state.security_events.append(event)

    output_state = runtime.execute(state)

    assert output_state.errors == []
    assert len(output_state.detection_results) == 1
    assert len(output_state.analysis_results) == 1
    assert len(output_state.decision_results) == 1
    assert output_state.decision_results[0].analysis_id == output_state.analysis_results[0].analysis_id
    # A real DDoS median vector must actually be detected as an attack —
    # the previous version asserted only that three objects were produced,
    # which a zero-filled vector classified as BENIGN also satisfied.
    assert output_state.detection_results[0].predicted_label == "DDOS"
    assert output_state.detection_results[0].status == DetectionStatus.DETECTED
