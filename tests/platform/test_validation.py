"""Tests for shared validation rules."""

import pytest

from cyber_surakshya.platform.validation.rules import (
    ensure_severity_matches_risk,
    validate_confidence,
    validate_ip_address,
    validate_probability_map,
)


def test_validate_ip_address_accepts_ipv4_and_ipv6():
    assert validate_ip_address("192.168.0.1") == "192.168.0.1"
    assert validate_ip_address("::1") == "::1"


def test_validate_ip_address_rejects_invalid():
    with pytest.raises(ValueError, match="Invalid IP"):
        validate_ip_address("not-an-ip")


def test_validate_confidence_bounds():
    assert validate_confidence(0.5) == 0.5
    with pytest.raises(ValueError):
        validate_confidence(1.5)


def test_validate_probability_map():
    result = validate_probability_map({"A": 0.6, "B": 0.4})
    assert result["A"] == 0.6


def test_validate_probability_map_rejects_overflow():
    with pytest.raises(ValueError, match="must not exceed"):
        validate_probability_map({"A": 0.9, "B": 0.9})


def test_ensure_severity_matches_risk_allows_one_level_drift():
    from cyber_surakshya.platform.enums.severity import Severity

    ensure_severity_matches_risk(Severity.HIGH, 45.0, allow_one_level_drift=True)


def test_ensure_severity_matches_risk_rejects_large_drift():
    from cyber_surakshya.platform.enums.severity import Severity

    with pytest.raises(ValueError, match="inconsistent"):
        ensure_severity_matches_risk(
            Severity.INFO, 90.0, allow_one_level_drift=False
        )
