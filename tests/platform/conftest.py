"""Shared fixtures for platform schema tests."""

from __future__ import annotations

from cyber_surakshya.platform.audit.metadata import AuditMetadata
from cyber_surakshya.platform.enums.detection_status import DetectionStatus
from cyber_surakshya.platform.enums.event_source import EventSource
from cyber_surakshya.platform.enums.event_type import EventType
from cyber_surakshya.platform.enums.severity import Severity
from cyber_surakshya.platform.identifiers.correlation import CorrelationContext
from cyber_surakshya.platform.risk.score import RiskScore
from cyber_surakshya.platform.schemas.alert import Alert
from cyber_surakshya.platform.schemas.detection_result import DetectionResult
from cyber_surakshya.platform.schemas.security_event import NetworkEndpoint, SecurityEvent


def sample_audit(*, actor: str = "platform") -> AuditMetadata:
    return AuditMetadata(
        created_by=actor,
        updated_by=actor,
        source_system="platform",
    )


def sample_context() -> CorrelationContext:
    return CorrelationContext.create()


def sample_security_event(
    context: CorrelationContext | None = None,
    *,
    severity: Severity = Severity.HIGH,
    risk_value: float = 72.5,
) -> SecurityEvent:
    ctx = context or sample_context()
    return SecurityEvent(
        correlation_id=ctx.correlation_id,
        trace_id=ctx.trace_id,
        event_type=EventType.NETWORK_FLOW,
        source=EventSource.IDS,
        severity=severity,
        risk_score=RiskScore(value=risk_value),
        title="Suspicious network flow",
        description="High packet rate toward port 80",
        network=NetworkEndpoint(
            source_ip="192.168.1.10",
            destination_ip="10.0.0.5",
            destination_port=80,
            protocol="tcp",
        ),
        features={"Flow Packets/s": 20000.0},
        audit=sample_audit(actor="ids"),
    )


def sample_detection_result(
    event: SecurityEvent,
    *,
    status: DetectionStatus = DetectionStatus.DETECTED,
    predicted_label: str = "DDoS",
) -> DetectionResult:
    return DetectionResult(
        event_id=event.event_id,
        correlation_id=event.correlation_id,
        trace_id=event.trace_id,
        status=status,
        severity=event.severity,
        risk_score=event.risk_score,
        model_name="RandomForest",
        model_version="1.0.0",
        predicted_label=predicted_label,
        confidence=0.9912,
        probabilities={"DDoS": 0.9912, "BENIGN": 0.0088},
        is_anomaly=status == DetectionStatus.DETECTED,
        feature_snapshot=event.features,
        audit=sample_audit(actor="ids"),
    )


def sample_alert(
    event: SecurityEvent,
    detection: DetectionResult,
) -> Alert:
    return Alert(
        correlation_id=event.correlation_id,
        trace_id=event.trace_id,
        severity=event.severity,
        risk_score=event.risk_score,
        title="DDoS activity detected",
        description="Model flagged SYN flood pattern",
        event_ids=[event.event_id],
        detection_ids=[detection.detection_id],
        recommended_actions=["Block source IP", "Notify SOC"],
        audit=sample_audit(actor="platform"),
    )
