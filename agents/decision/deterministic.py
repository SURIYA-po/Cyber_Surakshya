"""Deterministic, rule-based decision engine — no LLM dependency.

Implements the DecisionEngine Protocol from agents/decision/base.py.
Evaluated top-to-bottom; the first matching PolicyRule wins.

Rules are generic thresholds, not attack-specific labels.
To add a new rule for any attack class, append a PolicyRule to RULES.
No changes are needed in DecisionAgent or DecisionResult.

Future replacement without changing DecisionAgent:
  - OllamaDecisionEngine  (local LLM via Ollama)
  - ClaudeDecisionEngine  (Anthropic Claude API)
  - GPTDecisionEngine     (OpenAI GPT-4 API)
"""
from __future__ import annotations

from cyber_surakshya.platform.actions.action import Action
from cyber_surakshya.platform.actions.action_parameters import ActionParameters
from cyber_surakshya.platform.actions.action_target import ActionTarget
from cyber_surakshya.platform.actions.action_type import ActionType
from cyber_surakshya.platform.enums.detection_status import DetectionStatus
from cyber_surakshya.platform.enums.severity import Severity
from cyber_surakshya.platform.schemas.decision_result import (
    ApprovalStatus,
    DecisionPriority,
)
from agents.decision.base import DecisionContext, DecisionDraft
from agents.decision.exceptions import PolicyEvaluationError
from agents.decision.policy import PolicyCondition, PolicyRule

# Severity ordering used for >= comparisons (IntEnum provides this naturally,
# but we make the ordering semantics explicit for clarity).
_SEVERITY_ORDER: list[Severity] = [
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]


class DeterministicDecisionEngine:
    """Evaluates a fixed, ordered rule table to produce a DecisionDraft.

    Rules are pure data (PolicyRule dataclasses). Conditions are generic
    numeric/enum thresholds — no DDoS, bot, or brute-force labels.

    The rule table can later be loaded from a YAML/database at __init__
    time without changing DecisionAgent or DecisionResult.
    """

    engine_name:    str = "DeterministicDecisionEngine"
    engine_version: str = "1.0.0"
    policy_version: str = "1.0.0"

    # ── Rule table (top-to-bottom; first match wins) ───────────────────────
    RULES: list[PolicyRule] = [
        # Rule 1: CRITICAL severity + high risk → auto-block, no approval needed.
        # Covers: volumetric DDoS, zero-day exploits, ransomware beaconing, etc.
        PolicyRule(
            name="critical_high_risk_auto_block",
            conditions=PolicyCondition(
                min_severity=Severity.CRITICAL,
                min_risk=80.0,
            ),
            action_type=ActionType.BLOCK_IP,
            target_type="IP",
            priority=DecisionPriority.CRITICAL,
            requires_approval=False,
            approval_status=ApprovalStatus.AUTO_APPROVED,
            rationale_template=(
                "CRITICAL severity with risk score {risk:.0f}/100. "
                "Automated inline containment is warranted without analyst approval."
            ),
            confidence_score=0.95,
        ),
        # Rule 2: Entity with ≥2 prior incidents → host isolation, requires approval.
        # Covers: repeat attackers, persistent threats, slow-burn lateral movement.
        PolicyRule(
            name="repeat_offender_isolate",
            conditions=PolicyCondition(
                min_memory_hits=2,
            ),
            action_type=ActionType.ISOLATE_HOST,
            target_type="IP",
            priority=DecisionPriority.CRITICAL,
            requires_approval=True,
            approval_status=ApprovalStatus.PENDING,
            rationale_template=(
                "Entity has {memory_hits} prior incident record(s). "
                "Host isolation is recommended — awaiting analyst approval."
            ),
            confidence_score=0.90,
        ),
        # Rule 3: HIGH severity + high confidence + DETECTED → notify SOC.
        # Covers: credential attacks, port scans, C2 beaconing at moderate confidence.
        PolicyRule(
            name="high_confidence_detected_notify",
            conditions=PolicyCondition(
                min_severity=Severity.HIGH,
                min_confidence=0.75,
                required_detection_status=DetectionStatus.DETECTED,
            ),
            action_type=ActionType.NOTIFY_SOC,
            target_type="IP",
            priority=DecisionPriority.HIGH,
            requires_approval=False,
            approval_status=ApprovalStatus.AUTO_APPROVED,
            rationale_template=(
                "HIGH severity detection at {confidence:.0%} confidence. "
                "SOC notification dispatched for analyst review."
            ),
            confidence_score=0.85,
        ),
        # Rule 4: MEDIUM severity detected → rate limit and notify.
        PolicyRule(
            name="medium_severity_rate_limit",
            conditions=PolicyCondition(
                min_severity=Severity.MEDIUM,
                required_detection_status=DetectionStatus.DETECTED,
            ),
            action_type=ActionType.RATE_LIMIT,
            target_type="IP",
            priority=DecisionPriority.MEDIUM,
            requires_approval=False,
            approval_status=ApprovalStatus.AUTO_APPROVED,
            rationale_template=(
                "MEDIUM severity detection with risk {risk:.0f}/100. "
                "Rate limiting applied to reduce attack surface."
            ),
            confidence_score=0.80,
        ),
        # Rule 5: INCONCLUSIVE detection → SOC review (anomaly signal present
        # but supervised classifier is uncertain).
        PolicyRule(
            name="inconclusive_soc_review",
            conditions=PolicyCondition(
                required_detection_status=DetectionStatus.INCONCLUSIVE,
            ),
            action_type=ActionType.NOTIFY_SOC,
            target_type="IP",
            priority=DecisionPriority.MEDIUM,
            requires_approval=False,
            approval_status=ApprovalStatus.AUTO_APPROVED,
            rationale_template=(
                "Inconclusive detection result. Anomaly signal is present but the "
                "supervised classifier is uncertain. Manual SOC review is recommended."
            ),
            confidence_score=0.70,
        ),
        # Rule 6: BENIGN catch-all → log only. Must be last.
        PolicyRule(
            name="benign_log_only",
            conditions=PolicyCondition(
                required_detection_status=DetectionStatus.BENIGN,
            ),
            action_type=ActionType.LOG_ONLY,
            target_type="IP",
            priority=DecisionPriority.LOW,
            requires_approval=False,
            approval_status=ApprovalStatus.AUTO_APPROVED,
            rationale_template=(
                "Benign traffic confirmed at risk {risk:.0f}/100. "
                "Logged for audit continuity — no action required."
            ),
            confidence_score=0.99,
        ),
    ]

    def make_decision(self, context: DecisionContext) -> DecisionDraft:
        """Evaluate the rule table top-to-bottom; return first match.

        Raises:
            PolicyEvaluationError: No rule matched (incomplete rule table).
        """
        memory_hits = len(context.historical_records)
        risk        = context.detection_result.risk_score.value
        severity    = context.analysis_result.severity
        confidence  = context.detection_result.confidence
        det_status  = context.detection_result.status

        for rule in self.RULES:
            if self._matches(rule.conditions, severity, risk, confidence,
                             memory_hits, det_status):
                target_value = self._resolve_target(context)
                action = Action(
                    action_type=rule.action_type,
                    target=ActionTarget(
                        target_type=rule.target_type,
                        target_value=target_value,
                    ),
                    parameters=ActionParameters(),
                )
                rationale = rule.rationale_template.format(
                    risk=risk,
                    confidence=confidence,
                    memory_hits=memory_hits,
                )
                return DecisionDraft(
                    action=action,
                    priority=rule.priority,
                    requires_approval=rule.requires_approval,
                    approval_status=rule.approval_status,
                    rationale=rationale,
                    confidence=rule.confidence_score,
                    policy_name=rule.name,
                    memory_hits=memory_hits,
                )

        raise PolicyEvaluationError(
            f"No policy rule matched the detection context "
            f"(severity={severity!s}, risk={risk:.1f}, "
            f"status={det_status!s}, memory_hits={memory_hits}). "
            "Add a catch-all rule to the RULES table."
        )

    # ── Private helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _matches(
        cond: PolicyCondition,
        severity: Severity,
        risk: float,
        confidence: float,
        memory_hits: int,
        det_status: DetectionStatus,
    ) -> bool:
        """Return True when all specified conditions are satisfied."""
        if cond.min_severity is not None:
            if _SEVERITY_ORDER.index(severity) < _SEVERITY_ORDER.index(cond.min_severity):
                return False
        if cond.min_risk is not None and risk < cond.min_risk:
            return False
        if cond.min_confidence is not None and confidence < cond.min_confidence:
            return False
        if cond.min_memory_hits is not None and memory_hits < cond.min_memory_hits:
            return False
        if (cond.required_detection_status is not None
                and det_status != cond.required_detection_status):
            return False
        return True

    @staticmethod
    def _resolve_target(context: DecisionContext) -> str:
        """Extract the target value from the security event.

        Prefers source_ip from network metadata. Falls back to the
        event_id when network context is unavailable.
        """
        network = getattr(context.security_event, "network", None)
        if network is not None:
            source_ip = getattr(network, "source_ip", None)
            if source_ip:
                return source_ip
        return context.security_event.event_id
