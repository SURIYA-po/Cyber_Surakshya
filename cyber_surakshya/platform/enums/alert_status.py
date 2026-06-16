"""Alert lifecycle status values."""

from enum import StrEnum


class AlertStatus(StrEnum):
    """Lifecycle states for security alerts."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    SUPPRESSED = "suppressed"
