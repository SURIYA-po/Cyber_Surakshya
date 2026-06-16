"""Tests for risk score and severity mapping."""

import pytest

from cyber_surakshya.platform.enums.risk_level import RiskLevel
from cyber_surakshya.platform.enums.severity import Severity
from cyber_surakshya.platform.risk.score import (
    RiskScore,
    risk_level_from_score,
    severity_from_risk_score,
)


@pytest.mark.parametrize(
    ("score", "expected_level"),
    [
        (0.0, RiskLevel.NEGLIGIBLE),
        (19.99, RiskLevel.NEGLIGIBLE),
        (20.0, RiskLevel.LOW),
        (59.99, RiskLevel.MODERATE),
        (80.0, RiskLevel.CRITICAL),
        (100.0, RiskLevel.CRITICAL),
    ],
)
def test_risk_level_from_score(score, expected_level):
    assert risk_level_from_score(score) == expected_level


@pytest.mark.parametrize(
    ("score", "expected_severity"),
    [
        (10.0, Severity.INFO),
        (25.0, Severity.LOW),
        (45.0, Severity.MEDIUM),
        (70.0, Severity.HIGH),
        (90.0, Severity.CRITICAL),
    ],
)
def test_severity_from_risk_score(score, expected_severity):
    assert severity_from_risk_score(score) == expected_severity


def test_risk_score_auto_derives_level():
    score = RiskScore(value=75.0)
    assert score.level == RiskLevel.HIGH


def test_risk_score_rejects_out_of_range():
    with pytest.raises(ValueError):
        RiskScore(value=101.0)
