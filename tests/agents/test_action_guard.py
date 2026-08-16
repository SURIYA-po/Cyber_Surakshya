"""Tests for ActionGuard — the authorisation gate protecting real-world actions.

The central concern is §2 of docs/plans/response_agent_plan.md: the guard must
stay safe when the decision engine is a language model rather than a bounded
rule table.
"""
from __future__ import annotations

from dataclasses import replace

import pytest

from agents.response.config import BlastRadiusPolicy, ResponsePolicyConfig
from agents.response.guard import ActionGuard
from cyber_surakshya.platform.actions.action_type import ActionType
from cyber_surakshya.platform.schemas.decision_result import ApprovalStatus
from cyber_surakshya.platform.schemas.response_result import (
    EngineTrustTier,
    GuardVerdict,
)
from tests.agents.conftest import (
    DETERMINISTIC_ENGINE,
    LLM_ENGINE,
    UNREGISTERED_ENGINE,
    make_decision,
)

# ── Engine trust matrix (§2.1) ────────────────────────────────────────────────


def test_deterministic_engine_may_self_authorise_destructive_action(policy):
    guard = ActionGuard(policy)
    decision = make_decision(decision_engine=DETERMINISTIC_ENGINE, confidence=0.95)

    verdict = guard.evaluate(decision)

    assert verdict.verdict is GuardVerdict.ALLOW
    assert verdict.tier is EngineTrustTier.DETERMINISTIC


def test_llm_engine_cannot_self_authorise_destructive_action(policy):
    """The headline invariant: an LLM's AUTO_APPROVED block requires a human.

    The decision is AUTO_APPROVED — the engine approving its own output —
    which must not satisfy the gate that exists to supervise that engine.
    """
    guard = ActionGuard(policy)
    decision = make_decision(
        decision_engine=LLM_ENGINE,
        confidence=0.99,
        approval_status=ApprovalStatus.AUTO_APPROVED,
    )

    verdict = guard.evaluate(decision, human_approved=False)

    assert verdict.verdict is GuardVerdict.REQUIRE_APPROVAL
    assert verdict.tier is EngineTrustTier.AI_SUPERVISED
    assert verdict.rule == "trust_ai_supervised_requires_approval"


def test_llm_engine_executes_destructive_action_once_a_human_approves(policy):
    guard = ActionGuard(policy)
    decision = make_decision(decision_engine=LLM_ENGINE, confidence=0.99)

    verdict = guard.evaluate(decision, human_approved=True)

    assert verdict.verdict is GuardVerdict.ALLOW
    assert verdict.tier is EngineTrustTier.AI_SUPERVISED


def test_llm_engine_may_notify_without_approval(policy):
    """AI_SUPERVISED must stay useful — it can raise the alarm unassisted."""
    guard = ActionGuard(policy)
    decision = make_decision(
        decision_engine=LLM_ENGINE,
        action_type=ActionType.NOTIFY_SOC,
        confidence=0.40,
    )

    verdict = guard.evaluate(decision)

    assert verdict.verdict is GuardVerdict.ALLOW


def test_unregistered_engine_is_downgraded_not_approved(policy):
    """Fail-closed: an engine nobody vouched for cannot reach a human queue."""
    guard = ActionGuard(policy)
    decision = make_decision(decision_engine=UNREGISTERED_ENGINE, confidence=1.0)

    verdict = guard.evaluate(decision)

    assert verdict.verdict is GuardVerdict.DOWNGRADE
    assert verdict.tier is EngineTrustTier.UNKNOWN
    assert verdict.action.action_type is ActionType.NOTIFY_SOC
    assert verdict.substituted is True


@pytest.mark.parametrize(
    "engine,confidence",
    [
        (DETERMINISTIC_ENGINE, 0.60),   # tier floor 0.70
        (LLM_ENGINE, 0.85),             # tier floor 0.90
    ],
)
def test_confidence_below_tier_threshold_requires_approval(policy, engine, confidence):
    guard = ActionGuard(policy)
    decision = make_decision(decision_engine=engine, confidence=confidence)

    verdict = guard.evaluate(decision)

    assert verdict.verdict is GuardVerdict.REQUIRE_APPROVAL
    assert "below the" in verdict.reason


def test_downgrade_target_is_never_destructive(policy):
    """A downgrade must reduce impact; it can never become an escalation."""
    guard = ActionGuard(policy)
    decision = make_decision(decision_engine=UNREGISTERED_ENGINE)

    verdict = guard.evaluate(decision)

    assert not policy.is_destructive(verdict.action.action_type)
    assert verdict.action.target.target_value == decision.action.target.target_value


# ── Structural validation (§2.2) ──────────────────────────────────────────────


def test_malformed_ip_target_is_denied(policy):
    guard = ActionGuard(policy)
    decision = make_decision(target_value="not-an-ip-address")

    verdict = guard.evaluate(decision)

    assert verdict.verdict is GuardVerdict.DENY
    assert verdict.rule == "malformed_target_value"


def test_incoherent_action_target_pair_is_denied(policy):
    """BLOCK_IP on a FILE target is nonsense however confident the engine is."""
    guard = ActionGuard(policy)
    decision = make_decision(
        action_type=ActionType.BLOCK_IP,
        target_type="FILE",
        target_value="/tmp/payload.bin",
    )

    verdict = guard.evaluate(decision)

    assert verdict.verdict is GuardVerdict.DENY
    assert verdict.rule == "incoherent_action_target"


def test_malformed_hostname_is_denied(policy):
    guard = ActionGuard(policy)
    decision = make_decision(
        action_type=ActionType.ISOLATE_HOST,
        target_type="HOST",
        target_value="not a valid hostname!",
    )

    verdict = guard.evaluate(decision)

    assert verdict.verdict is GuardVerdict.DENY
    assert verdict.rule == "malformed_target_value"


def test_notification_verbs_accept_any_target_class(policy):
    guard = ActionGuard(policy)
    decision = make_decision(
        action_type=ActionType.NOTIFY_SOC,
        target_type="FILE",
        target_value="/var/log/suspicious.log",
    )

    assert guard.evaluate(decision).verdict is GuardVerdict.ALLOW


# ── Protected targets ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "address", ["127.0.0.1", "169.254.10.5", "224.0.0.1", "255.255.255.255"]
)
def test_protected_ranges_are_denied(policy, address):
    guard = ActionGuard(policy)
    decision = make_decision(target_value=address)

    verdict = guard.evaluate(decision)

    assert verdict.verdict is GuardVerdict.DENY
    assert verdict.rule == "protected_target"


def test_protected_host_is_denied(policy):
    guarded = replace(
        policy,
        protected_targets=replace(policy.protected_targets, hosts=("dc01.corp.local",)),
    )
    guard = ActionGuard(guarded)
    decision = make_decision(
        action_type=ActionType.ISOLATE_HOST,
        target_type="HOST",
        target_value="DC01.corp.local",     # case-insensitive match
    )

    assert guard.evaluate(decision).rule == "protected_target"


def test_notification_about_a_protected_target_is_allowed(policy):
    """Protection blocks action, not awareness."""
    guard = ActionGuard(policy)
    decision = make_decision(action_type=ActionType.NOTIFY_SOC, target_value="127.0.0.1")

    assert guard.evaluate(decision).verdict is GuardVerdict.ALLOW


def test_critical_asset_requires_approval(policy):
    guard = ActionGuard(policy)
    decision = make_decision(asset_criticality="CRITICAL")

    verdict = guard.evaluate(decision)

    assert verdict.verdict is GuardVerdict.REQUIRE_APPROVAL
    assert verdict.rule == "critical_asset_requires_approval"


def test_critical_asset_proceeds_with_analyst_approval(policy):
    guard = ActionGuard(policy)
    decision = make_decision(asset_criticality="CRITICAL")

    assert guard.evaluate(decision, human_approved=True).verdict is GuardVerdict.ALLOW


# ── Blast radius (§2.3) ───────────────────────────────────────────────────────


def test_per_correlation_limit_downgrades_further_actions(policy):
    limited = replace(
        policy,
        blast_radius=BlastRadiusPolicy(
            max_destructive_per_correlation=2,
            max_destructive_per_target_window_seconds=900,
            global_destructive_per_minute=100,
        ),
    )
    guard = ActionGuard(limited)
    first = make_decision(target_value="203.0.113.1")

    for index, address in enumerate(["203.0.113.1", "203.0.113.2"]):
        decision = make_decision(
            target_value=address,
            correlation_context=_context_of(first),
        )
        assert guard.evaluate(decision).verdict is GuardVerdict.ALLOW, index

    third = make_decision(target_value="203.0.113.3", correlation_context=_context_of(first))
    verdict = guard.evaluate(third)

    assert verdict.verdict is GuardVerdict.DOWNGRADE
    assert verdict.rule == "blast_radius_correlation"


def test_repeat_action_on_same_target_is_downgraded_within_window(policy):
    guard = ActionGuard(policy)

    assert guard.evaluate(make_decision(target_value="203.0.113.50")).verdict is GuardVerdict.ALLOW
    repeat = guard.evaluate(make_decision(target_value="203.0.113.50"))

    assert repeat.verdict is GuardVerdict.DOWNGRADE
    assert repeat.rule == "blast_radius_target_window"


def test_global_circuit_breaker_trips(policy):
    tripped = replace(
        policy,
        blast_radius=BlastRadiusPolicy(
            max_destructive_per_correlation=100,
            max_destructive_per_target_window_seconds=900,
            global_destructive_per_minute=3,
        ),
    )
    guard = ActionGuard(tripped)

    for index in range(3):
        decision = make_decision(target_value=f"203.0.113.{100 + index}")
        assert guard.evaluate(decision).verdict is GuardVerdict.ALLOW

    verdict = guard.evaluate(make_decision(target_value="203.0.113.200"))

    assert verdict.verdict is GuardVerdict.DOWNGRADE
    assert verdict.rule == "blast_radius_circuit_breaker"


def test_non_destructive_actions_do_not_consume_blast_budget(policy):
    starved = replace(
        policy,
        blast_radius=BlastRadiusPolicy(
            max_destructive_per_correlation=1,
            max_destructive_per_target_window_seconds=900,
            global_destructive_per_minute=1,
        ),
    )
    guard = ActionGuard(starved)

    for _ in range(5):
        decision = make_decision(action_type=ActionType.NOTIFY_SOC)
        assert guard.evaluate(decision).verdict is GuardVerdict.ALLOW


# ── Parameters and dry run ────────────────────────────────────────────────────


def test_out_of_range_duration_is_clamped_not_rejected(policy):
    guard = ActionGuard(policy)
    decision = make_decision(duration_seconds=10 * 365 * 24 * 3600)   # ten years

    verdict = guard.evaluate(decision)

    assert verdict.verdict is GuardVerdict.ALLOW
    assert verdict.action.parameters.duration_seconds == policy.max_action_duration_seconds


def test_short_duration_is_raised_to_the_floor(policy):
    guard = ActionGuard(policy)
    decision = make_decision(duration_seconds=1)

    verdict = guard.evaluate(decision)

    assert verdict.action.parameters.duration_seconds == policy.min_action_duration_seconds


def test_global_dry_run_downgrades_execution_to_simulation(policy):
    guard = ActionGuard(replace(policy, dry_run=True))

    verdict = guard.evaluate(make_decision())

    assert verdict.verdict is GuardVerdict.ALLOW_DRY_RUN
    assert verdict.dry_run is True
    assert verdict.permits_execution is True


def test_per_action_dry_run_is_honoured(policy):
    guard = ActionGuard(policy)

    verdict = guard.evaluate(make_decision(dry_run=True))

    assert verdict.verdict is GuardVerdict.ALLOW_DRY_RUN


# ── Configuration behaviour (§10) ─────────────────────────────────────────────


def test_missing_config_file_yields_fail_closed_defaults(tmp_path):
    config = ResponsePolicyConfig.load(tmp_path / "does_not_exist.yaml")

    assert config.loaded_from_defaults is True
    assert config.engine_trust == {"DeterministicDecisionEngine": EngineTrustTier.DETERMINISTIC}
    assert config.tier_policy(EngineTrustTier.UNKNOWN).destructive_allowed is False
    assert config.protected_targets.covers_ip("127.0.0.1") is True


def test_corrupt_config_file_yields_fail_closed_defaults(tmp_path):
    path = tmp_path / "broken.yaml"
    path.write_text("engine_trust: [this is not a mapping\n", encoding="utf-8")

    config = ResponsePolicyConfig.load(path)

    assert config.loaded_from_defaults is True


def test_unknown_tier_cannot_be_widened_by_configuration(tmp_path):
    """UNKNOWN staying fail-closed is a platform invariant, not a preference."""
    path = tmp_path / "permissive.yaml"
    path.write_text(
        "trust_tiers:\n"
        "  UNKNOWN:\n"
        "    destructive_allowed: true\n"
        "    min_confidence: 0.0\n",
        encoding="utf-8",
    )

    config = ResponsePolicyConfig.load(path)

    assert config.tier_policy(EngineTrustTier.UNKNOWN).destructive_allowed is False


def test_destructive_downgrade_action_is_rejected(tmp_path):
    """The safety net must never be configurable into an escalation path."""
    path = tmp_path / "escalating.yaml"
    path.write_text("downgrade_action: ISOLATE_HOST\n", encoding="utf-8")

    config = ResponsePolicyConfig.load(path)

    assert config.downgrade_action is ActionType.NOTIFY_SOC


def test_enabling_an_llm_engine_is_configuration_only(tmp_path):
    """Proves decision 1 of §10: no code change to onboard a new engine."""
    path = tmp_path / "with_llm.yaml"
    path.write_text(
        "engine_trust:\n"
        "  DeterministicDecisionEngine: DETERMINISTIC\n"
        "  ClaudeDecisionEngine: AI_SUPERVISED\n",
        encoding="utf-8",
    )
    config = ResponsePolicyConfig.load(path)
    guard = ActionGuard(config)

    verdict = guard.evaluate(make_decision(decision_engine="ClaudeDecisionEngine"))

    assert verdict.tier is EngineTrustTier.AI_SUPERVISED
    assert verdict.verdict is GuardVerdict.REQUIRE_APPROVAL


# ── Helpers ───────────────────────────────────────────────────────────────────


def _context_of(decision):
    from cyber_surakshya.platform.identifiers.correlation import (
        CorrelationContext,
        generate_session_id,
    )

    return CorrelationContext(
        correlation_id=decision.correlation_id,
        trace_id=decision.trace_id,
        session_id=generate_session_id(),
    )
