"""ActionGuard — the last authorisation gate before a real-world side-effect.

Everything upstream of this module decides what *should* happen. This module
decides what is *allowed* to happen, and it assumes the action it is handed
may have been produced by a language model.

Evaluation order (first non-ALLOW verdict wins):

  1. Structural validity — does the target parse as the type it claims, and is
     the verb meaningful for that target class?
  2. Protected targets   — loopback, link-local, multicast, the platform's own
     address, operator-listed hosts.
  3. Asset criticality   — critical assets always involve a human.
  4. Engine trust        — may this engine, at this confidence, do this?
  5. Blast radius        — has this run, this target, or the platform as a
     whole already done too much?
  6. Dry run             — global kill-switch.

A verdict may reduce impact (DOWNGRADE, REQUIRE_APPROVAL, DENY). It may never
increase it: the substitute action is validated to be non-destructive, so the
safety net cannot become an escalation path.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import threading
import time
from dataclasses import dataclass, field

from agents.response.config import ResponsePolicyConfig
from agents.response.trust import EngineTrustPolicy
from cyber_surakshya.platform.actions.action import Action
from cyber_surakshya.platform.actions.action_parameters import ActionParameters
from cyber_surakshya.platform.actions.action_target import ActionTarget
from cyber_surakshya.platform.actions.action_type import ActionType
from cyber_surakshya.platform.schemas.decision_result import DecisionResult
from cyber_surakshya.platform.schemas.response_result import (
    EngineTrustTier,
    GuardVerdict,
)

logger = logging.getLogger(__name__)

# Verb → target classes the verb is semantically meaningful for. Independent
# of which executors happen to be registered: this is domain coherence, not
# routing. BLOCK_IP on a FILE target is nonsense regardless of integrations.
_ACTION_TARGET_COHERENCE: dict[ActionType, frozenset[str]] = {
    ActionType.BLOCK_IP:            frozenset({"IP"}),
    ActionType.UNBLOCK_IP:          frozenset({"IP"}),
    ActionType.ISOLATE_HOST:        frozenset({"IP", "HOST"}),
    ActionType.RELEASE_HOST:        frozenset({"IP", "HOST"}),
    ActionType.RATE_LIMIT:          frozenset({"IP", "HOST", "ENDPOINT"}),
    ActionType.QUARANTINE_FILE:     frozenset({"FILE"}),
    ActionType.TERMINATE_PROCESS:   frozenset({"PROCESS"}),
    ActionType.REVOKE_CREDENTIALS:  frozenset({"USER", "ACCOUNT"}),
    # Informational verbs may reference any entity class.
    ActionType.NOTIFY_SOC:          frozenset(),
    ActionType.OPEN_TICKET:         frozenset(),
    ActionType.ENRICH_THREAT_INTEL: frozenset(),
    ActionType.LOG_ONLY:            frozenset(),
}

_HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)


@dataclass(frozen=True)
class GuardDecision:
    """The guard's authorisation verdict for one action."""

    verdict:    GuardVerdict
    rule:       str
    reason:     str
    tier:       EngineTrustTier
    action:     Action                 # the action to execute (post-substitution)
    substituted: bool = False

    @property
    def permits_execution(self) -> bool:
        """True when an executor should be invoked."""
        return self.verdict in (GuardVerdict.ALLOW, GuardVerdict.ALLOW_DRY_RUN)

    @property
    def dry_run(self) -> bool:
        """True when execution must produce no side-effect."""
        return self.verdict is GuardVerdict.ALLOW_DRY_RUN


@dataclass
class _BlastRadiusLedger:
    """Time-windowed counters bounding destructive activity.

    Budget is consumed at authorisation rather than after successful
    execution: an action that was authorised and then failed still tells us
    the engine tried, which is the signal a runaway loop produces.
    """

    per_correlation: dict[str, int]         = field(default_factory=dict)
    per_target:      dict[tuple[str, str], float] = field(default_factory=dict)
    global_events:   list[float]            = field(default_factory=list)


class ActionGuard:
    """Authorises actions against the response policy.

    Thread-safe: blast-radius counters are shared across concurrent requests.
    """

    def __init__(
        self,
        config: ResponsePolicyConfig | None = None,
        *,
        trust_policy: EngineTrustPolicy | None = None,
    ) -> None:
        self.config       = config or ResponsePolicyConfig()
        self.trust_policy = trust_policy or EngineTrustPolicy(self.config)
        self._lock        = threading.Lock()
        self._ledger      = _BlastRadiusLedger()

    # ── Public API ────────────────────────────────────────────────────────────

    def evaluate(
        self,
        decision: DecisionResult,
        *,
        human_approved: bool = False,
    ) -> GuardDecision:
        """Authorise (or refuse) the action carried by a decision.

        Args:
            decision: the DecisionResult to authorise.
            human_approved: True when an analyst has explicitly approved this
                decision. Satisfies gates that would otherwise defer to a
                human; never overrides DENY.
        """
        action = decision.action
        tier   = self.trust_policy.tier_for(decision.decision_engine)

        structural = self._check_structure(action, tier)
        if structural is not None:
            return structural

        protected = self._check_protected_target(action, tier)
        if protected is not None:
            return protected

        normalized = self._normalize_parameters(action)

        criticality = self._check_asset_criticality(normalized, tier, human_approved)
        if criticality is not None:
            return criticality

        trust = self._check_trust(decision, normalized, tier, human_approved)
        if trust is not None:
            return trust

        blast = self._check_blast_radius(decision, normalized, tier)
        if blast is not None:
            return blast

        if self.config.dry_run or normalized.parameters.dry_run:
            return GuardDecision(
                verdict=GuardVerdict.ALLOW_DRY_RUN,
                rule="dry_run_mode",
                reason=(
                    "Global dry-run mode is enabled."
                    if self.config.dry_run
                    else "Action parameters requested a dry run."
                ),
                tier=tier,
                action=normalized,
            )

        self._consume_budget(decision, normalized)
        return GuardDecision(
            verdict=GuardVerdict.ALLOW,
            rule="authorised",
            reason=(
                f"{normalized.action_type.value} authorised for trust tier "
                f"{tier.value}"
                + (" with analyst approval." if human_approved else ".")
            ),
            tier=tier,
            action=normalized,
        )

    # ── Rules ─────────────────────────────────────────────────────────────────

    def _check_structure(
        self,
        action: Action,
        tier: EngineTrustTier,
    ) -> GuardDecision | None:
        """Reject actions that are malformed or semantically incoherent.

        A model can emit a syntactically valid Action describing something
        impossible. Catching that here means an executor never sees it.
        """
        target_type  = action.target.target_type.upper()
        target_value = action.target.target_value

        allowed_targets = _ACTION_TARGET_COHERENCE.get(action.action_type)
        if allowed_targets is None:
            return self._deny(
                "unknown_action_type",
                f"{action.action_type.value} has no coherence definition; "
                "refusing to execute an unclassified verb.",
                tier,
                action,
            )
        if allowed_targets and target_type not in allowed_targets:
            return self._deny(
                "incoherent_action_target",
                f"{action.action_type.value} is not meaningful for a "
                f"{target_type} target (expected one of "
                f"{sorted(allowed_targets)}).",
                tier,
                action,
            )

        if target_type == "IP":
            try:
                ipaddress.ip_address(target_value)
            except ValueError:
                return self._deny(
                    "malformed_target_value",
                    f"Target {target_value!r} is declared as an IP but does not "
                    "parse as one.",
                    tier,
                    action,
                )
        elif target_type == "HOST":
            if not _HOSTNAME_PATTERN.match(target_value):
                return self._deny(
                    "malformed_target_value",
                    f"Target {target_value!r} is declared as a HOST but is not a "
                    "valid hostname.",
                    tier,
                    action,
                )
        elif target_type == "PROCESS":
            if not target_value.strip():
                return self._deny(
                    "malformed_target_value",
                    "PROCESS target is empty.",
                    tier,
                    action,
                )
        return None

    def _check_protected_target(
        self,
        action: Action,
        tier: EngineTrustTier,
    ) -> GuardDecision | None:
        """Refuse to act on infrastructure the platform must never touch."""
        if not self.config.is_destructive(action.action_type):
            return None

        target_type  = action.target.target_type.upper()
        target_value = action.target.target_value
        protected    = self.config.protected_targets

        if target_type == "IP" and protected.covers_ip(target_value):
            return self._deny(
                "protected_target",
                f"{target_value} falls within a protected range. Destructive "
                "actions against platform or network infrastructure are refused.",
                tier,
                action,
            )
        if target_type == "HOST" and protected.covers_host(target_value):
            return self._deny(
                "protected_target",
                f"Host {target_value!r} is on the protected host list.",
                tier,
                action,
            )
        return None

    def _check_asset_criticality(
        self,
        action: Action,
        tier: EngineTrustTier,
        human_approved: bool,
    ) -> GuardDecision | None:
        """Route actions against critical assets through a human.

        ``asset_criticality`` stays None until an AssetInventory component
        populates it; reading it opportunistically means this rule activates
        with no rewrite when that lands.
        """
        criticality = (action.target.asset_criticality or "").upper()
        if not criticality:
            return None
        if criticality not in self.config.approval_required_asset_criticality:
            return None
        if not self.config.is_destructive(action.action_type):
            return None
        if human_approved:
            return None
        return GuardDecision(
            verdict=GuardVerdict.REQUIRE_APPROVAL,
            rule="critical_asset_requires_approval",
            reason=(
                f"Target is a {criticality} asset. Destructive actions against "
                "critical assets require analyst approval."
            ),
            tier=tier,
            action=action,
        )

    def _check_trust(
        self,
        decision: DecisionResult,
        action: Action,
        tier: EngineTrustTier,
        human_approved: bool,
    ) -> GuardDecision | None:
        """Apply the engine trust policy (see trust.py)."""
        assessment = self.trust_policy.assess(
            decision_engine=decision.decision_engine,
            action_type=action.action_type,
            confidence=decision.confidence,
        )
        if assessment.authorised:
            return None

        if assessment.requires_human:
            if human_approved:
                # An analyst supplied the authority the engine lacked. This is
                # exactly the AI_SUPERVISED workflow completing successfully.
                return None
            return GuardDecision(
                verdict=GuardVerdict.REQUIRE_APPROVAL,
                rule=f"trust_{assessment.tier.value.lower()}_requires_approval",
                reason=assessment.reason,
                tier=assessment.tier,
                action=action,
            )

        return self._downgrade(
            rule="untrusted_engine_downgrade",
            reason=assessment.reason,
            tier=assessment.tier,
            action=action,
        )

    def _check_blast_radius(
        self,
        decision: DecisionResult,
        action: Action,
        tier: EngineTrustTier,
    ) -> GuardDecision | None:
        """Bound how much destruction one run — or the platform — can cause."""
        if not self.config.is_destructive(action.action_type):
            return None

        limits = self.config.blast_radius
        now    = time.monotonic()
        key    = (action.target.target_value, action.action_type.value)

        with self._lock:
            self._prune_locked(now)

            used = self._ledger.per_correlation.get(decision.correlation_id, 0)
            if used >= limits.max_destructive_per_correlation:
                return self._downgrade(
                    rule="blast_radius_correlation",
                    reason=(
                        f"This workflow has already authorised {used} destructive "
                        f"action(s), reaching the limit of "
                        f"{limits.max_destructive_per_correlation}. Further "
                        "containment is escalated to the SOC instead."
                    ),
                    tier=tier,
                    action=action,
                )

            last = self._ledger.per_target.get(key)
            if last is not None:
                window = limits.max_destructive_per_target_window_seconds
                if now - last < window:
                    return self._downgrade(
                        rule="blast_radius_target_window",
                        reason=(
                            f"{action.action_type.value} was already applied to "
                            f"{action.target.target_value} "
                            f"{int(now - last)}s ago, inside the {window}s "
                            "per-target window."
                        ),
                        tier=tier,
                        action=action,
                    )

            if len(self._ledger.global_events) >= limits.global_destructive_per_minute:
                logger.error(
                    "response_guard_circuit_breaker_tripped",
                    extra={
                        "authorised_last_minute": len(self._ledger.global_events),
                        "limit": limits.global_destructive_per_minute,
                        "decision_engine": decision.decision_engine,
                        "trust_tier": tier.value,
                    },
                )
                return self._downgrade(
                    rule="blast_radius_circuit_breaker",
                    reason=(
                        f"Platform-wide circuit breaker tripped: "
                        f"{len(self._ledger.global_events)} destructive actions "
                        f"authorised in the last minute (limit "
                        f"{limits.global_destructive_per_minute}). All further "
                        "containment is escalated to the SOC until the rate falls."
                    ),
                    tier=tier,
                    action=action,
                )
        return None

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _normalize_parameters(self, action: Action) -> Action:
        """Clamp time-limited durations into the configured band.

        Clamped rather than rejected: an out-of-range duration is a bad
        parameter, not a bad decision, and a 10-year block silently becoming
        24 hours is safer than either extreme.
        """
        duration = action.parameters.duration_seconds
        if duration is None:
            return action
        low, high = (
            self.config.min_action_duration_seconds,
            self.config.max_action_duration_seconds,
        )
        clamped = max(low, min(high, duration))
        if clamped == duration:
            return action

        logger.info(
            "response_guard_duration_clamped",
            extra={
                "requested": duration,
                "applied":   clamped,
                "action":    action.action_type.value,
            },
        )
        return Action(
            action_type=action.action_type,
            target=action.target,
            parameters=ActionParameters(
                duration_seconds=clamped,
                scope=action.parameters.scope,
                dry_run=action.parameters.dry_run,
                custom=dict(action.parameters.custom),
            ),
        )

    def _consume_budget(self, decision: DecisionResult, action: Action) -> None:
        """Record an authorised destructive action against the blast budget."""
        if not self.config.is_destructive(action.action_type):
            return
        now = time.monotonic()
        key = (action.target.target_value, action.action_type.value)
        with self._lock:
            self._prune_locked(now)
            self._ledger.per_correlation[decision.correlation_id] = (
                self._ledger.per_correlation.get(decision.correlation_id, 0) + 1
            )
            self._ledger.per_target[key] = now
            self._ledger.global_events.append(now)

    def _prune_locked(self, now: float) -> None:
        """Drop expired ledger entries. Caller must hold the lock."""
        self._ledger.global_events = [
            ts for ts in self._ledger.global_events if now - ts < 60.0
        ]
        window = self.config.blast_radius.max_destructive_per_target_window_seconds
        self._ledger.per_target = {
            key: ts for key, ts in self._ledger.per_target.items() if now - ts < window
        }

    def _deny(
        self,
        rule: str,
        reason: str,
        tier: EngineTrustTier,
        action: Action,
    ) -> GuardDecision:
        logger.warning(
            "response_guard_denied",
            extra={
                "rule":        rule,
                "action_type": action.action_type.value,
                "target":      action.target.target_value,
                "trust_tier":  tier.value,
            },
        )
        return GuardDecision(
            verdict=GuardVerdict.DENY,
            rule=rule,
            reason=reason,
            tier=tier,
            action=action,
        )

    def _downgrade(
        self,
        *,
        rule: str,
        reason: str,
        tier: EngineTrustTier,
        action: Action,
    ) -> GuardDecision:
        """Substitute a non-destructive action, preserving the target."""
        substitute_type = self.config.downgrade_action
        if self.config.is_destructive(substitute_type):
            # Defence in depth: config.py already rejects a destructive
            # downgrade target, so reaching here means the invariant was
            # bypassed. Deny rather than escalate.
            return self._deny(
                "downgrade_target_destructive",
                f"Configured downgrade action {substitute_type.value} is "
                "destructive; refusing to substitute.",
                tier,
                action,
            )

        logger.info(
            "response_guard_downgraded",
            extra={
                "rule":        rule,
                "from_action": action.action_type.value,
                "to_action":   substitute_type.value,
                "target":      action.target.target_value,
                "trust_tier":  tier.value,
            },
        )
        substitute = Action(
            action_type=substitute_type,
            target=ActionTarget(
                target_type=action.target.target_type,
                target_value=action.target.target_value,
                asset_criticality=action.target.asset_criticality,
                metadata={
                    **action.target.metadata,
                    "downgraded_from": action.action_type.value,
                },
            ),
            parameters=ActionParameters(
                scope=action.parameters.scope,
                dry_run=action.parameters.dry_run,
            ),
        )
        return GuardDecision(
            verdict=GuardVerdict.DOWNGRADE,
            rule=rule,
            reason=reason,
            tier=tier,
            action=substitute,
            substituted=True,
        )
