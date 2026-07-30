"""Generic, data-driven policy rule structures.

Rules are pure data: conditions evaluated by DeterministicDecisionEngine.
No attack-type names (DDoS, BruteForce, Bot) are encoded here.
Attack-specific knowledge belongs in a future Threat Intelligence component.

Conditions use only numeric/enum thresholds:
  - Severity (IntEnum ordered INFO < LOW < MEDIUM < HIGH < CRITICAL)
  - RiskScore (float 0–100)
  - Confidence (float 0.0–1.0)
  - Memory hits (int — prior incidents for the same entity)
  - DetectionStatus (DETECTED | BENIGN | INCONCLUSIVE | ERROR)

Adding a new rule tomorrow (e.g. for malware, ransomware, data exfiltration)
requires only a new PolicyRule entry in DeterministicDecisionEngine.RULES.
No code changes in DecisionAgent or DecisionResult are needed.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from cyber_surakshya.platform.actions.action_type import ActionType
from cyber_surakshya.platform.enums.detection_status import DetectionStatus
from cyber_surakshya.platform.enums.severity import Severity
from cyber_surakshya.platform.schemas.decision_result import (
    ApprovalStatus,
    DecisionPriority,
)


@dataclass(frozen=True)
class PolicyCondition:
    """Threshold guard for a policy rule.

    All specified conditions must match simultaneously (AND logic).
    Leave a field as None to make it unconditional for that dimension.
    """

    min_severity:              Severity        | None = None
    min_risk:                  float           | None = None  # 0–100
    min_confidence:            float           | None = None  # 0.0–1.0
    min_memory_hits:           int             | None = None  # prior incidents
    required_detection_status: DetectionStatus | None = None


@dataclass(frozen=True)
class PolicyRule:
    """One entry in the deterministic policy rule table.

    Rules are evaluated top-to-bottom; the first match wins.
    ``rationale_template`` supports {risk:.0f}, {confidence:.0%},
    {memory_hits} format placeholders — filled at evaluation time.
    ``confidence_score`` is the engine's confidence in this rule's
    applicability (written to DecisionResult.confidence).
    """

    name:               str
    conditions:         PolicyCondition
    action_type:        ActionType
    target_type:        str               # "IP", "HOST", "FILE", "PROCESS" …
    priority:           DecisionPriority
    requires_approval:  bool
    approval_status:    ApprovalStatus
    rationale_template: str
    confidence_score:   float             # 0.0–1.0
