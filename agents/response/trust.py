"""Engine trust policy — how much authority a decision engine carries.

DecisionAgent treats engines as interchangeable behind the DecisionEngine
Protocol. That is correct for decision-making and unsafe for execution: a
rule table has a bounded output space, a language model does not.

This module resolves DecisionResult.decision_engine to an EngineTrustTier and
answers one question for the guard: may a decision from this engine, at this
confidence, execute this action without a human?

Registration is explicit. An engine nobody has vouched for is UNKNOWN, and
UNKNOWN can never authorise anything destructive.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from agents.response.config import ResponsePolicyConfig
from cyber_surakshya.platform.actions.action_type import ActionType
from cyber_surakshya.platform.schemas.response_result import EngineTrustTier

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TrustAssessment:
    """The trust layer's verdict on one decision.

    ``authorised`` means the action may proceed to execution as-is.
    When False, ``requires_human`` distinguishes "a human could authorise
    this" (REQUIRE_APPROVAL) from "this is not authorisable" (DOWNGRADE).
    """

    tier:           EngineTrustTier
    authorised:     bool
    requires_human: bool
    reason:         str


class EngineTrustPolicy:
    """Resolves engine identity to execution authority."""

    def __init__(self, config: ResponsePolicyConfig | None = None) -> None:
        self.config = config or ResponsePolicyConfig()

    def tier_for(self, decision_engine: str) -> EngineTrustTier:
        """Return the trust tier registered for an engine name.

        Unregistered engines resolve to UNKNOWN. This is the fail-closed
        default that makes enabling a new engine a deliberate act.
        """
        tier = self.config.engine_trust.get(decision_engine)
        if tier is None:
            logger.warning(
                "response_trust_unregistered_engine",
                extra={"decision_engine": decision_engine},
            )
            return EngineTrustTier.UNKNOWN
        return tier

    def assess(
        self,
        *,
        decision_engine: str,
        action_type: ActionType,
        confidence: float,
    ) -> TrustAssessment:
        """Decide whether an engine may execute an action unassisted."""
        tier   = self.tier_for(decision_engine)
        policy = self.config.tier_policy(tier)

        if not self.config.is_destructive(action_type):
            # Non-destructive verbs (notify, ticket, enrich, log) are open to
            # every tier. This is what keeps an AI_SUPERVISED engine useful
            # rather than inert — it can raise the alarm, just not pull triggers.
            return TrustAssessment(
                tier=tier,
                authorised=True,
                requires_human=False,
                reason=(
                    f"{action_type.value} is non-destructive; "
                    f"permitted for trust tier {tier.value}."
                ),
            )

        if confidence < policy.min_confidence:
            return TrustAssessment(
                tier=tier,
                authorised=False,
                requires_human=tier is not EngineTrustTier.UNKNOWN,
                reason=(
                    f"Decision confidence {confidence:.2f} is below the "
                    f"{policy.min_confidence:.2f} threshold required for "
                    f"destructive actions at trust tier {tier.value}."
                ),
            )

        if not policy.destructive_allowed:
            if tier is EngineTrustTier.UNKNOWN:
                return TrustAssessment(
                    tier=tier,
                    authorised=False,
                    requires_human=False,
                    reason=(
                        f"Engine {decision_engine!r} is not registered in the "
                        "response policy. Unregistered engines may not perform "
                        f"{action_type.value}."
                    ),
                )
            return TrustAssessment(
                tier=tier,
                authorised=False,
                requires_human=True,
                reason=(
                    f"Trust tier {tier.value} may not self-authorise "
                    f"{action_type.value}. A language model cannot approve its "
                    "own destructive action — analyst approval is required."
                ),
            )

        return TrustAssessment(
            tier=tier,
            authorised=True,
            requires_human=False,
            reason=(
                f"Trust tier {tier.value} authorises {action_type.value} at "
                f"confidence {confidence:.2f}."
            ),
        )
