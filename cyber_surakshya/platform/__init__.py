"""
Shared platform state and security event schemas.

This package defines domain models, Pydantic schemas, validation rules,
and LangGraph-compatible shared state structures used across the platform.
Future agents consume these types but are not implemented here.
"""

from cyber_surakshya.platform.audit.metadata import AuditMetadata
from cyber_surakshya.platform.enums import (
    AlertStatus,
    DetectionStatus,
    EventSource,
    EventType,
    RiskLevel,
    Severity,
)
from cyber_surakshya.platform.identifiers.correlation import (
    CorrelationContext,
    generate_correlation_id,
    generate_event_id,
    generate_trace_id,
)
from cyber_surakshya.platform.risk.score import RiskScore, severity_from_risk_score
from cyber_surakshya.platform.schemas.alert import Alert
from cyber_surakshya.platform.schemas.detection_result import DetectionResult
from cyber_surakshya.platform.schemas.security_event import SecurityEvent
from cyber_surakshya.platform.state import (
    PlatformSharedState,
    PlatformStateModel,
    create_initial_state,
)

__all__ = [
    "Alert",
    "AlertStatus",
    "AuditMetadata",
    "CorrelationContext",
    "DetectionResult",
    "DetectionStatus",
    "EventSource",
    "EventType",
    "PlatformSharedState",
    "PlatformStateModel",
    "RiskLevel",
    "RiskScore",
    "SecurityEvent",
    "Severity",
    "create_initial_state",
    "generate_correlation_id",
    "generate_event_id",
    "generate_trace_id",
    "severity_from_risk_score",
]
