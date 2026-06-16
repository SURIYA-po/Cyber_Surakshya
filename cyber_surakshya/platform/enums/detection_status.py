"""Detection outcome status values."""

from enum import StrEnum


class DetectionStatus(StrEnum):
    """Outcome of a detection pipeline run against an event."""

    DETECTED = "detected"
    BENIGN = "benign"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"
