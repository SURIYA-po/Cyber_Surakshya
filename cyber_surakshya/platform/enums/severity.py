"""Severity levels for security events and alerts."""

from enum import IntEnum


class Severity(IntEnum):
    """
    Ordered severity levels for security observations.

    Higher numeric values indicate greater urgency. Used consistently across
    events, detection results, and alerts.
    """

    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    @classmethod
    def from_label(cls, label: str) -> "Severity":
        """Parse a severity label (case-insensitive)."""
        normalized = label.strip().upper()
        try:
            return cls[normalized]
        except KeyError as exc:
            raise ValueError(f"Unknown severity label: {label!r}") from exc

    @property
    def label(self) -> str:
        return self.name
