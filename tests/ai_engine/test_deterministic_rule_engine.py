"""Tests for the deterministic AI engine."""

from ai_engine.base import AnalysisContext
from ai_engine.deterministic import DeterministicRuleEngine
from cyber_surakshya.platform.enums.detection_status import DetectionStatus
from cyber_surakshya.platform.schemas.analysis_result import AnalysisResult
from tests.platform.conftest import sample_detection_result, sample_security_event


def test_deterministic_rule_engine_returns_valid_analysis_result():
    event = sample_security_event()
    detection = sample_detection_result(event)
    engine = DeterministicRuleEngine()

    result = engine.analyze(
        AnalysisContext(security_event=event, detection_result=detection)
    )

    assert isinstance(result, AnalysisResult)
    assert result.event_id == event.event_id
    assert result.detection_id == detection.detection_id
    assert result.correlation_id == detection.correlation_id
    assert result.trace_id == detection.trace_id
    assert result.severity == detection.severity
    assert result.risk_score == detection.risk_score
    assert result.confidence == detection.confidence
    assert result.metadata["engine"] == "deterministic_rule_engine"


def test_deterministic_rule_engine_produces_detection_evidence():
    event = sample_security_event()
    detection = sample_detection_result(event)

    result = DeterministicRuleEngine().analyze(
        AnalysisContext(security_event=event, detection_result=detection)
    )

    evidence_names = {item.name for item in result.evidence}
    assert "predicted_label" in evidence_names
    assert "confidence" in evidence_names
    assert "risk_score" in evidence_names
    assert "probability:DDoS" in evidence_names
    assert "Flow Packets/s" in evidence_names


def test_deterministic_rule_engine_records_uncertainty():
    event = sample_security_event()
    detection = sample_detection_result(
        event,
        status=DetectionStatus.INCONCLUSIVE,
        predicted_label="DDoS",
    ).model_copy(
        update={
            "confidence": 0.45,
            "probabilities": {},
            "feature_snapshot": {},
        }
    )

    result = DeterministicRuleEngine().analyze(
        AnalysisContext(security_event=event, detection_result=detection)
    )

    assert "Detection status is inconclusive." in result.uncertainty
    assert "Detection confidence is below 0.60." in result.uncertainty
    assert "Class probability map is unavailable." in result.uncertainty
