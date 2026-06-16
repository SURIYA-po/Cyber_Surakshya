"""Shared validation rules for platform schemas."""

from __future__ import annotations

import ipaddress
from typing import Any

from cyber_surakshya.platform.enums.severity import Severity
from cyber_surakshya.platform.risk.score import severity_from_risk_score


def validate_ip_address(value: str | None) -> str | None:
    """Validate an IPv4 or IPv6 address string."""
    if value is None:
        return None
    stripped = value.strip()
    if not stripped:
        raise ValueError("IP address must not be empty.")
    try:
        ipaddress.ip_address(stripped)
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {value!r}") from exc
    return stripped


def validate_port(value: int | None) -> int | None:
    """Validate a TCP/UDP port number."""
    if value is None:
        return None
    if not 0 <= value <= 65535:
        raise ValueError(f"Port must be between 0 and 65535, got {value}.")
    return value


def validate_confidence(value: float) -> float:
    """Validate a model confidence score in [0, 1]."""
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"Confidence must be between 0.0 and 1.0, got {value}.")
    return round(value, 6)


def validate_probability_map(probabilities: dict[str, float]) -> dict[str, float]:
    """Validate class probability map entries and optional sum."""
    if not probabilities:
        raise ValueError("Probability map must not be empty.")
    validated: dict[str, float] = {}
    total = 0.0
    for label, prob in probabilities.items():
        if not label.strip():
            raise ValueError("Probability labels must be non-empty.")
        if not 0.0 <= prob <= 1.0:
            raise ValueError(
                f"Probability for {label!r} must be in [0, 1], got {prob}."
            )
        validated[label] = round(prob, 6)
        total += prob
    if total > 1.0001:
        raise ValueError(
            f"Sum of probabilities must not exceed 1.0, got {total:.6f}."
        )
    return validated


def validate_non_empty_dict_keys(data: dict[str, Any]) -> dict[str, Any]:
    """Ensure dictionary keys are non-empty strings."""
    for key in data:
        if not str(key).strip():
            raise ValueError("Dictionary keys must be non-empty.")
    return data


def ensure_severity_matches_risk(
    severity: Severity,
    risk_score: float,
    *,
    allow_one_level_drift: bool = True,
) -> None:
    """
    Raise ValueError when severity diverges too far from the risk score.

    By default one severity level of drift is permitted to support manual
    analyst overrides without blocking ingestion.
    """
    expected = severity_from_risk_score(risk_score)
    drift = abs(int(severity) - int(expected))
    max_drift = 1 if allow_one_level_drift else 0
    if drift > max_drift:
        raise ValueError(
            f"Severity {severity.label} is inconsistent with risk score "
            f"{risk_score} (expected ~{expected.label})."
        )
