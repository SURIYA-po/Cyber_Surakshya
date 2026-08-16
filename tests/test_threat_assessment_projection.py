"""Read-model tests for the Threat Assessment projection.

The card these feed had no calculation behind it: its score was the alert's
`confidence_score`, which fell back to the literal 95 whenever no analysis
record existed. These tests pin the replacement — every value is read back
from what the agents persisted, and an absent measurement stays absent.
"""
from datetime import datetime, timezone

import pytest

from api.projections import (
    alert_status,
    build_alert_detail_payload,
    build_alerts_from_memory_records,
    build_threat_assessment,
    normalize_severity,
)
from memory.models import MemoryRecord


def detection_content(**overrides):
    content = {
        "detection_id": "det-1",
        "event_id": "evt-1",
        "predicted_label": "PortScan",
        "confidence": 0.91,
        "status": "detected",
        "risk_score": 36.4,
        "risk_level": "LOW",
        "risk_rationale": "PortScan at 91% confidence (class base risk 40/100).",
        "severity_label": "LOW",
        "severity_value": 2,
        "is_anomaly": False,
        "detection_source": "ids_detection_adapter",
        "model_name": "RandomForestClassifier",
    }
    content.update(overrides)
    return content


# ── Score, band, and the absence of fallbacks ────────────────────────────────


@pytest.mark.parametrize(
    "score,level,band",
    [
        (0.0,   "NEGLIGIBLE", [0.0, 19.99]),
        (45.0,  "MODERATE",   [40.0, 59.99]),
        (80.0,  "CRITICAL",   [80.0, 100.0]),
        (100.0, "CRITICAL",   [80.0, 100.0]),
    ],
)
def test_score_carries_its_band(score, level, band):
    # risk_level omitted so the band is recovered from the score alone, which
    # is what records written before risk_level was persisted look like.
    assessment = build_threat_assessment(
        detection_content(risk_score=score, risk_level=None)
    )
    assert assessment["score"] == score
    assert assessment["level"] == level
    # The band travels with the level so the client styles by membership
    # instead of re-declaring thresholds and drifting from RISK_BANDS.
    assert assessment["band"] == band


def test_missing_risk_score_is_none_not_a_stand_in():
    assessment = build_threat_assessment(
        detection_content(risk_score=None, risk_level=None)
    )
    assert assessment["score"] is None
    assert assessment["level"] is None
    assert assessment["band"] is None


def test_detail_payload_never_invents_a_confidence():
    """The `else 95` regression: a bare detection must not report 95/100."""
    record = MemoryRecord(
        backend="qdrant_sqlite",
        collection="detections",
        record_type="detection_result",
        entity_id="10.0.0.9",
        content={"detection_id": "old-1", "predicted_label": "PortScan"},
        created_at=datetime(2026, 8, 1, tzinfo=timezone.utc),
    )
    alert = build_alerts_from_memory_records([record])[0]
    payload = build_alert_detail_payload(alert)

    assert payload["confidence_score"] is None
    assert payload["threat_assessment"]["score"] is None
    # Prose asserting work that never happened is also a fabrication.
    assert payload["analysis_summary"] is None


# ── Detection status ─────────────────────────────────────────────────────────


def test_inconclusive_anomaly_is_not_resolved():
    """The screenshot case: BENIGN label, anomaly layer dissenting.

    Status used to be derived from the predicted label alone, so this — the one
    verdict meaning "worth an analyst's time" — rendered as "Resolved".
    """
    content = detection_content(
        predicted_label="BENIGN",
        status="inconclusive",
        risk_score=45.0,
        risk_level="MODERATE",
        severity_label="MEDIUM",
        severity_value=3,
        is_anomaly=True,
    )
    assessment = build_threat_assessment(content)

    assert assessment["score"] == 45.0
    assert assessment["level"] == "MODERATE"
    assert assessment["detection_status"] == "INCONCLUSIVE"
    assert assessment["is_anomaly"] is True
    assert alert_status("inconclusive", "BENIGN") == "Needs Review"


def test_benign_without_anomaly_scores_zero():
    assessment = build_threat_assessment(
        detection_content(
            predicted_label="BENIGN",
            status="benign",
            risk_score=0.0,
            risk_level="NEGLIGIBLE",
            severity_label="INFO",
            is_anomaly=False,
        )
    )
    assert assessment["score"] == 0.0
    assert assessment["level"] == "NEGLIGIBLE"
    assert assessment["is_anomaly"] is False
    assert alert_status("benign", "BENIGN") == "Resolved"


def test_detected_high_confidence():
    assessment = build_threat_assessment(
        detection_content(
            predicted_label="Bot", status="detected", risk_score=95.0,
            risk_level="CRITICAL", severity_label="CRITICAL", confidence=0.99,
        )
    )
    assert assessment["detection_status"] == "DETECTED"
    assert assessment["detection_confidence"] == 0.99
    assert alert_status("detected", "Bot") == "Investigating"


def test_unknown_status_falls_back_to_label_derivation():
    """Records written by a producer with its own status vocabulary."""
    assert alert_status("malicious", "DDoS") == "Investigating"
    assert alert_status(None, "BENIGN") == "Resolved"


# ── Severity format ──────────────────────────────────────────────────────────


def test_severity_ordinal_and_label_agree():
    """DetectionAgent persists the ordinal, the simulation router the name.

    Both reach this one consumer, which is why a real alert rendered its
    severity as the bare string "3".
    """
    assert normalize_severity(3) == "MEDIUM"
    assert normalize_severity("3") == "MEDIUM"
    assert normalize_severity("MEDIUM") == "MEDIUM"
    assert normalize_severity("critical") == "CRITICAL"
    # Unrecognized values pass through rather than being mapped to a guess.
    assert normalize_severity("9") == "9"


def test_severity_read_from_ordinal_metadata():
    assessment = build_threat_assessment(
        detection_content(severity_label=None), {"severity": 3}
    )
    assert assessment["severity"] == "MEDIUM"


# ── Confidence: two quantities, one scale ────────────────────────────────────


def test_detection_and_analysis_confidence_stay_distinct():
    assessment = build_threat_assessment(
        detection_content(confidence=0.99), None, {"confidence": 0.87}
    )
    assert assessment["detection_confidence"] == 0.99
    assert assessment["analysis_confidence"] == 0.87


def test_confidence_normalized_to_a_fraction():
    """A producer that stored a percentage must not read as 87.0 out of 1."""
    assessment = build_threat_assessment(
        detection_content(confidence=99.0), None, {"confidence": 87.0}
    )
    assert assessment["detection_confidence"] == 0.99
    assert assessment["analysis_confidence"] == 0.87


def test_analysis_confidence_absent_without_an_analysis():
    assessment = build_threat_assessment(detection_content())
    assert assessment["analysis_confidence"] is None


# ── Decision and provenance ──────────────────────────────────────────────────


@pytest.mark.parametrize(
    "action,priority,requires_approval",
    [
        ("BLOCK_IP",     "CRITICAL", False),
        ("ISOLATE_HOST", "CRITICAL", True),
        ("NOTIFY_SOC",   "MEDIUM",   False),
        ("LOG_ONLY",     "LOW",      False),
    ],
)
def test_decision_block_reports_what_was_decided(action, priority, requires_approval):
    assessment = build_threat_assessment(
        detection_content(),
        decision={
            "action_type": action,
            "action_target_value": "10.0.0.5",
            "priority": priority,
            "requires_approval": requires_approval,
            "approval_status": "PENDING" if requires_approval else "NOT_REQUIRED",
            "rationale": "Policy rule 1 matched.",
            "confidence": 0.95,
            "decision_engine": "DeterministicDecisionEngine",
        },
    )
    decision = assessment["decision"]
    assert decision["action"] == action
    assert decision["target"] == "10.0.0.5"
    assert decision["priority"] == priority
    assert decision["requires_approval"] is requires_approval
    assert decision["rationale"] == "Policy rule 1 matched."
    assert assessment["provenance"]["decision_engine"] == "DeterministicDecisionEngine"


def test_decision_absent_when_none_was_recorded():
    assert build_threat_assessment(detection_content())["decision"] is None


def test_provenance_names_each_engine():
    assessment = build_threat_assessment(
        detection_content(),
        None,
        {"confidence": 0.8, "engine": "DeterministicRuleEngine"},
        {"decision_engine": "DeterministicDecisionEngine"},
    )
    assert assessment["provenance"] == {
        "detection_source": "ids_detection_adapter",
        "detection_model": "RandomForestClassifier",
        "analysis_engine": "DeterministicRuleEngine",
        "decision_engine": "DeterministicDecisionEngine",
    }


def test_mitre_is_null_until_a_real_mapping_exists():
    """The frontend hardcoded T1190 for every alert, benign ones included."""
    assert build_threat_assessment(detection_content())["mitre"] is None


# ── End to end through the alert projection ──────────────────────────────────


def test_alert_and_detail_agree_on_the_assessment():
    record = MemoryRecord(
        backend="qdrant_sqlite",
        collection="detections",
        record_type="detection_result",
        entity_id="10.51.13.14",
        content=detection_content(
            predicted_label="BENIGN", status="inconclusive", risk_score=45.0,
            risk_level="MODERATE", severity_label="MEDIUM", severity_value=3,
            is_anomaly=True,
        ),
        metadata={"severity": 3, "severity_label": "MEDIUM"},
        created_at=datetime(2026, 8, 9, 8, 2, 26, tzinfo=timezone.utc),
    )
    alert = build_alerts_from_memory_records([record])[0]
    payload = build_alert_detail_payload(alert)

    assert alert["severity"] == "MEDIUM"
    assert alert["status"] == "Needs Review"
    assert payload["threat_assessment"] == alert["threat_assessment"]
    assert payload["threat_assessment"]["score"] == 45.0
    # Threat score and confidence are no longer the same number.
    assert payload["confidence_score"] == 91.0
