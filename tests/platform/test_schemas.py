"""Tests for security event, detection result, and alert schemas."""

import pytest

from cyber_surakshya.platform.enums.alert_status import AlertStatus
from cyber_surakshya.platform.enums.detection_status import DetectionStatus
from cyber_surakshya.platform.enums.severity import Severity
from cyber_surakshya.platform.risk.score import RiskScore
from cyber_surakshya.platform.schemas.alert import Alert
from cyber_surakshya.platform.schemas.detection_result import DetectionResult
from cyber_surakshya.platform.schemas.security_event import SecurityEvent
from tests.platform.conftest import (
    sample_alert,
    sample_detection_result,
    sample_security_event,
)


def test_security_event_validates_successfully():
    event = sample_security_event()
    assert event.event_type.value == "network_flow"
    assert event.network is not None
    assert event.network.destination_port == 80


def test_security_event_rejects_invalid_ip():
    from cyber_surakshya.platform.schemas.security_event import NetworkEndpoint

    with pytest.raises(ValueError, match="Invalid IP"):
        NetworkEndpoint(source_ip="999.999.999.999")


def test_security_event_rejects_severity_mismatch():
    with pytest.raises(ValueError, match="inconsistent"):
        sample_security_event(severity=Severity.INFO, risk_value=90.0)


def test_detection_result_validates_successfully():
    event = sample_security_event()
    detection = sample_detection_result(event)
    assert detection.status == DetectionStatus.DETECTED
    assert detection.event_id == event.event_id


def test_detection_result_rejects_benign_anomaly():
    event = sample_security_event()
    with pytest.raises(ValueError, match="Benign detections"):
        DetectionResult(
            **{
                **sample_detection_result(event).model_dump(),
                "status": DetectionStatus.BENIGN,
                "is_anomaly": True,
            }
        )


def test_detection_result_rejects_detected_with_benign_label():
    event = sample_security_event()
    with pytest.raises(ValueError, match="non-benign"):
        DetectionResult(
            **{
                **sample_detection_result(event).model_dump(),
                "predicted_label": "BENIGN",
            }
        )


def test_alert_validates_successfully():
    event = sample_security_event()
    detection = sample_detection_result(event)
    alert = sample_alert(event, detection)
    assert alert.status == AlertStatus.OPEN
    assert event.event_id in alert.event_ids


def test_alert_requires_linked_records():
    event = sample_security_event()
    detection = sample_detection_result(event)
    with pytest.raises(ValueError, match="at least one"):
        Alert(
            **{
                **sample_alert(event, detection).model_dump(),
                "event_ids": [],
                "detection_ids": [],
            }
        )


def test_alert_resolved_requires_timestamp():
    event = sample_security_event()
    detection = sample_detection_result(event)
    with pytest.raises(ValueError, match="resolved_at"):
        Alert(
            **{
                **sample_alert(event, detection).model_dump(),
                "status": AlertStatus.RESOLVED,
                "resolved_at": None,
            }
        )


def test_alert_with_status_updates_lifecycle():
    event = sample_security_event()
    detection = sample_detection_result(event)
    alert = sample_alert(event, detection)
    resolved = alert.with_status(
        AlertStatus.RESOLVED,
        updated_by="analyst-1",
    )
    assert resolved.status == AlertStatus.RESOLVED
    assert resolved.resolved_at is not None
    assert resolved.audit.updated_by == "analyst-1"
