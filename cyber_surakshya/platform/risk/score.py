"""Numeric risk score model and severity mapping."""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from cyber_surakshya.platform.enums.risk_level import RiskLevel
from cyber_surakshya.platform.enums.severity import Severity

# Inclusive lower bounds for each risk band on the 0–100 scale.
RISK_BANDS: dict[RiskLevel, tuple[float, float]] = {
    RiskLevel.NEGLIGIBLE: (0.0, 19.99),
    RiskLevel.LOW: (20.0, 39.99),
    RiskLevel.MODERATE: (40.0, 59.99),
    RiskLevel.HIGH: (60.0, 79.99),
    RiskLevel.CRITICAL: (80.0, 100.0),
}

RiskScoreValue = Annotated[
    float,
    Field(
        ge=0.0,
        le=100.0,
        description="Normalized risk score on a 0–100 scale.",
    ),
]


class RiskScore(BaseModel):
    """
    Validated risk score with derived risk level.

    Scores are normalized to 0–100. Risk level is computed automatically
    from defined band thresholds.
    """

    model_config = ConfigDict(extra="forbid")

    value: RiskScoreValue
    level: RiskLevel | None = Field(
        default=None,
        description="Derived risk band; computed from value when omitted.",
    )
    rationale: str | None = Field(
        default=None,
        max_length=1024,
        description="Optional human-readable explanation of the score.",
    )

    @field_validator("value")
    @classmethod
    def round_score(cls, value: float) -> float:
        return round(float(value), 4)

    @model_validator(mode="after")
    def derive_level(self) -> RiskScore:
        if self.level is None:
            self.level = risk_level_from_score(self.value)
        return self


def risk_level_from_score(score: float) -> RiskLevel:
    """Map a numeric score to its risk band."""
    clamped = max(0.0, min(100.0, score))
    for level in reversed(list(RiskLevel)):
        lower, upper = RISK_BANDS[level]
        if lower <= clamped <= upper:
            return level
    return RiskLevel.NEGLIGIBLE


def severity_from_risk_score(score: float) -> Severity:
    """
    Map a risk score to a platform severity level.

    Mapping aligns risk bands with operational severity so alerts and
    events stay consistent when only a numeric score is available.
    """
    level = risk_level_from_score(score)
    mapping: dict[RiskLevel, Severity] = {
        RiskLevel.NEGLIGIBLE: Severity.INFO,
        RiskLevel.LOW: Severity.LOW,
        RiskLevel.MODERATE: Severity.MEDIUM,
        RiskLevel.HIGH: Severity.HIGH,
        RiskLevel.CRITICAL: Severity.CRITICAL,
    }
    return mapping[level]
