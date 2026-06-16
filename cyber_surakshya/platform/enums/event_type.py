"""Security event type taxonomy."""

from enum import StrEnum


class EventType(StrEnum):
    """Categories of security-relevant observations."""

    NETWORK_FLOW = "network_flow"
    AUTH_ATTEMPT = "auth_attempt"
    MALWARE_DETECTED = "malware_detected"
    INTRUSION_ATTEMPT = "intrusion_attempt"
    POLICY_VIOLATION = "policy_violation"
    ANOMALY = "anomaly"
    SYSTEM_EVENT = "system_event"
    UNKNOWN = "unknown"
