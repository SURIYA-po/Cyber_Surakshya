"""Tests for response executors and the executor registry."""
from __future__ import annotations

import uuid

import pytest
from pydantic import BaseModel

from adapters.response import build_default_registry
from adapters.response.base import (
    ExecutionReceipt,
    ExecutionRequest,
    PermanentExecutorError,
    ResponseExecutor,
    RevertNotSupportedError,
)
from adapters.response.notification import NotificationExecutor
from adapters.response.registry import (
    DuplicateExecutorError,
    ExecutorRegistry,
    MissingExecutorError,
)
from adapters.response.simulated import SimulatedContainmentExecutor
from cyber_surakshya.platform.actions.action import Action
from cyber_surakshya.platform.actions.action_parameters import ActionParameters
from cyber_surakshya.platform.actions.action_target import ActionTarget
from cyber_surakshya.platform.actions.action_type import ActionType


def make_request(
    *,
    action_type: ActionType = ActionType.BLOCK_IP,
    target_type: str = "IP",
    target_value: str = "203.0.113.5",
    duration_seconds: int | None = None,
    dry_run: bool = False,
    custom: dict | None = None,
) -> ExecutionRequest:
    return ExecutionRequest(
        action=Action(
            action_type=action_type,
            target=ActionTarget(target_type=target_type, target_value=target_value),
            parameters=ActionParameters(
                duration_seconds=duration_seconds, custom=custom or {}
            ),
        ),
        correlation_id=str(uuid.uuid4()),
        trace_id=str(uuid.uuid4()),
        decision_id=str(uuid.uuid4()),
        idempotency_key="test-key",
        dry_run=dry_run,
    )


# ── Registry ──────────────────────────────────────────────────────────────────


def test_default_registry_routes_containment_and_notification():
    registry = build_default_registry()

    assert registry.resolve(ActionType.BLOCK_IP, "IP").executor_name == (
        "SimulatedContainmentExecutor"
    )
    assert registry.resolve(ActionType.NOTIFY_SOC, "IP").executor_name == (
        "NotificationExecutor"
    )


def test_registry_resolution_is_case_insensitive_for_target_type():
    registry = build_default_registry()

    assert registry.can_resolve(ActionType.BLOCK_IP, "ip")
    assert registry.can_resolve(ActionType.BLOCK_IP, "Ip")


@pytest.mark.parametrize(
    "action_type,target_type",
    [
        (ActionType.BLOCK_IP, "FILE"),
        (ActionType.QUARANTINE_FILE, "IP"),
        (ActionType.TERMINATE_PROCESS, "IP"),
    ],
)
def test_incoherent_pairs_are_not_routable(action_type, target_type):
    """Executors declare per-verb targets, so nonsense pairs never resolve."""
    registry = build_default_registry()

    assert not registry.can_resolve(action_type, target_type)
    with pytest.raises(MissingExecutorError):
        registry.resolve(action_type, target_type)


def test_duplicate_registration_is_rejected():
    registry = build_default_registry()

    with pytest.raises(DuplicateExecutorError):
        registry.register(SimulatedContainmentExecutor())


def test_override_replaces_an_existing_claim():
    """This is how a real integration supersedes the simulated one."""

    class RealFirewallExecutor(ResponseExecutor):
        executor_name    = "RealFirewallExecutor"
        executor_version = "2.0.0"
        action_targets   = {ActionType.BLOCK_IP: frozenset({"IP"})}

        def execute(self, request):
            return ExecutionReceipt(
                succeeded=True,
                executor_name=self.executor_name,
                executor_version=self.executor_version,
            )

    registry = build_default_registry()
    registry.register(RealFirewallExecutor(), override=True)

    assert registry.resolve(ActionType.BLOCK_IP, "IP").executor_name == (
        "RealFirewallExecutor"
    )
    # Unrelated routes are untouched.
    assert registry.resolve(ActionType.ISOLATE_HOST, "IP").executor_name == (
        "SimulatedContainmentExecutor"
    )


def test_executor_declaring_nothing_is_rejected():
    class EmptyExecutor(ResponseExecutor):
        executor_name = "EmptyExecutor"

        def execute(self, request):
            raise NotImplementedError

    with pytest.raises(ValueError):
        ExecutorRegistry().register(EmptyExecutor())


# ── Simulated containment executor ────────────────────────────────────────────


def test_containment_is_recorded_and_revertable():
    executor = SimulatedContainmentExecutor()

    receipt = executor.execute(make_request(target_value="198.51.100.4"))

    assert receipt.succeeded
    assert receipt.revert_token is not None
    assert executor.is_contained("198.51.100.4", ActionType.BLOCK_IP)

    executor.revert(receipt)

    assert not executor.is_contained("198.51.100.4", ActionType.BLOCK_IP)


def test_duration_sets_an_expiry():
    executor = SimulatedContainmentExecutor()

    receipt = executor.execute(make_request(duration_seconds=3600))

    assert receipt.expires_at is not None


def test_dry_run_produces_no_ledger_entry():
    executor = SimulatedContainmentExecutor()

    receipt = executor.execute(make_request(dry_run=True))

    assert receipt.succeeded
    assert receipt.details["ledger_written"] is False
    assert receipt.external_reference is None
    assert executor.active_entries() == ()


def test_inverse_action_clears_an_active_containment():
    """The simulated world stays coherent: UNBLOCK_IP really does unblock."""
    executor = SimulatedContainmentExecutor()
    executor.execute(make_request(target_value="198.51.100.9"))
    assert executor.is_contained("198.51.100.9", ActionType.BLOCK_IP)

    executor.execute(
        make_request(action_type=ActionType.UNBLOCK_IP, target_value="198.51.100.9")
    )

    assert not executor.is_contained("198.51.100.9", ActionType.BLOCK_IP)


def test_revert_without_a_token_is_refused():
    executor = SimulatedContainmentExecutor()

    with pytest.raises(PermanentExecutorError):
        executor.revert(
            ExecutionReceipt(
                succeeded=True,
                executor_name=executor.executor_name,
                executor_version=executor.executor_version,
            )
        )


def test_revert_with_an_unknown_token_is_refused():
    executor = SimulatedContainmentExecutor()

    with pytest.raises(PermanentExecutorError):
        executor.revert(
            ExecutionReceipt(
                succeeded=True,
                executor_name=executor.executor_name,
                executor_version=executor.executor_version,
                revert_token="nonexistent",
            )
        )


# ── Notification executor ─────────────────────────────────────────────────────


def test_notification_is_recorded_on_the_right_channel():
    executor = NotificationExecutor()

    receipt = executor.execute(make_request(action_type=ActionType.OPEN_TICKET))

    assert receipt.details["channel"] == "ticketing"
    assert len(executor.notifications()) == 1


def test_notification_is_not_revertable():
    """A sent alert cannot be un-sent, and the platform must not pretend."""
    executor = NotificationExecutor()
    receipt = executor.execute(make_request(action_type=ActionType.NOTIFY_SOC))

    assert receipt.revert_token is None
    with pytest.raises(RevertNotSupportedError):
        executor.revert(receipt)


def test_notification_dry_run_dispatches_nothing():
    executor = NotificationExecutor()

    receipt = executor.execute(
        make_request(action_type=ActionType.NOTIFY_SOC, dry_run=True)
    )

    assert receipt.details["dispatched"] is False
    assert executor.notifications() == ()


# ── Parameter sanitisation (§2.2) ─────────────────────────────────────────────


def test_undeclared_custom_parameters_are_dropped_not_forwarded():
    """A chatty LLM must not be able to smuggle fields into an integration."""

    class Params(BaseModel):
        policy_id: str | None = None

    class SchemaExecutor(ResponseExecutor):
        executor_name    = "SchemaExecutor"
        executor_version = "1.0.0"
        action_targets   = {ActionType.BLOCK_IP: frozenset({"IP"})}
        parameter_schema = Params

        def execute(self, request):
            return ExecutionReceipt(
                succeeded=True,
                executor_name=self.executor_name,
                executor_version=self.executor_version,
            )

    executor = SchemaExecutor()
    request = make_request(
        custom={"policy_id": "cs-42", "sudo": True, "exfiltrate": "/etc/shadow"}
    )

    sanitized = executor.sanitize_parameters(request.action)

    assert sanitized == {"policy_id": "cs-42"}


def test_executor_without_a_schema_receives_no_custom_parameters():
    executor = SimulatedContainmentExecutor()

    request = make_request(custom={"anything": "at all"})

    assert executor.sanitize_parameters(request.action) == {}
