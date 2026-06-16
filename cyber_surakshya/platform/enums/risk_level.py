"""Risk level bands derived from numeric risk scores."""

from enum import IntEnum


class RiskLevel(IntEnum):
    """
    Discrete risk bands mapped to the 0–100 risk score scale.

    Bands align with severity thresholds so downstream agents can reason
    about risk consistently without redefining cutoffs.
    """

    NEGLIGIBLE = 1
    LOW = 2
    MODERATE = 3
    HIGH = 4
    CRITICAL = 5

    @property
    def label(self) -> str:
        return self.name
