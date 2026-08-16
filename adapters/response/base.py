"""Base interfaces for response executors.

Mirrors adapters/detection/base.py. Executors are the outbound edge of the
platform — the only place where a real-world side-effect may occur.

ResponseAgent depends on this abstraction exclusively. Adding an integration
(iptables, pfSense, AWS Security Groups, CrowdStrike, SentinelOne, Wazuh,
TheHive, Slack) means adding one module here and one registry line. No agent,
schema, or guard code changes.

SAFETY CONSTRAINT: no module in adapters/response/ may import a network
client, subprocess, or cloud SDK until a real executor is an approved
component of its own. The shipped executors are simulation-only.
"""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from cyber_surakshya.platform.actions.action import Action
from cyber_surakshya.platform.actions.action_type import ActionType


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ExecutionRequest(BaseModel):
    """Everything an executor needs to perform one action.

    Grouped into a model so executor signatures never change when new
    contextual fields are added — the same pattern as DecisionContext.
    """

    model_config = ConfigDict(extra="forbid")

    action:          Action
    correlation_id:  str
    trace_id:        str
    decision_id:     str
    idempotency_key: str
    dry_run:         bool = Field(
        default=False,
        description="When True the executor must produce no side-effect.",
    )
    timeout_seconds: int = Field(default=30, ge=1, le=600)


class ExecutionReceipt(BaseModel):
    """Proof of what an executor did.

    ``external_reference`` is the identifier assigned by the target system,
    which is what makes a later revert possible. ``revert_token`` is opaque
    to the platform — only the issuing executor interprets it.
    """

    model_config = ConfigDict(extra="forbid")

    succeeded:          bool
    executor_name:      str
    executor_version:   str
    external_reference: str | None      = None
    revert_token:       str | None      = None
    expires_at:         datetime | None = None
    details:            dict[str, Any]  = Field(default_factory=dict)
    executed_at:        datetime        = Field(default_factory=_utc_now)


class ExecutorError(Exception):
    """Base error raised by a response executor."""


class TransientExecutorError(ExecutorError):
    """A retryable failure (timeout, temporary unavailability, rate limit).

    ResponseAgent retries only this class of error. Every other exception is
    treated as permanent, because blindly retrying an action with unknown
    side-effect status is more dangerous than failing.
    """


class PermanentExecutorError(ExecutorError):
    """A non-retryable failure (rejected request, unsupported target)."""


class RevertNotSupportedError(ExecutorError):
    """Raised when an executor cannot roll back the action it performed."""


class ResponseExecutor(ABC):
    """Common contract for response integrations.

    Subclasses declare what they can act on; the registry routes by
    ``(ActionType, target_type)`` so a future host or application-layer
    executor claims its actions without touching existing code.

    ``action_targets`` is the authoritative declaration: it maps each verb to
    exactly the target types that verb is meaningful for. A flat
    actions × targets cross-product would let an executor claim nonsense pairs
    such as BLOCK_IP on a FILE target, so routing is declared per verb.

    ``parameter_schema`` validates ``Action.parameters.custom``. Anything not
    declared by the schema is dropped rather than forwarded — an LLM decision
    engine may emit arbitrary keys, and they must never reach an integration.
    """

    executor_name:    str = "response_executor"
    executor_version: str = "1.0.0"
    action_targets:   dict[ActionType, frozenset[str]] = {}
    parameter_schema: type[BaseModel] | None = None

    @property
    def supported_actions(self) -> frozenset[ActionType]:
        """Verbs this executor can perform, for diagnostics."""
        return frozenset(self.action_targets)

    @property
    def supported_targets(self) -> frozenset[str]:
        """Target types this executor touches, for diagnostics."""
        return frozenset(
            target for targets in self.action_targets.values() for target in targets
        )

    @abstractmethod
    def execute(self, request: ExecutionRequest) -> ExecutionReceipt:
        """Perform one action and return a receipt.

        Raises:
            TransientExecutorError: retryable failure.
            PermanentExecutorError: non-retryable failure.
        """

    def revert(self, receipt: ExecutionReceipt) -> ExecutionReceipt:
        """Roll back a previously executed action.

        Default implementation refuses — an executor must opt in to rollback
        by overriding this, so an un-revertable action can never be silently
        reported as reverted.
        """
        raise RevertNotSupportedError(
            f"{self.executor_name} does not support reverting actions."
        )

    def health_check(self) -> bool:
        """Return True when the executor is able to accept work."""
        return True

    def supports(self, action_type: ActionType, target_type: str) -> bool:
        """Return True when this executor can handle the given pair."""
        return target_type.upper() in self.action_targets.get(action_type, frozenset())

    # ── Helpers for subclasses ────────────────────────────────────────────────

    def sanitize_parameters(self, action: Action) -> dict[str, Any]:
        """Validate ``parameters.custom`` against ``parameter_schema``.

        Unknown keys are dropped before validation rather than rejected, so a
        chatty LLM decision engine cannot fail an otherwise valid action — but
        cannot smuggle undeclared fields into an integration either.

        Returns an empty dict when no schema is declared, so an executor that
        has not opted into custom parameters never receives untrusted keys.
        """
        if self.parameter_schema is None:
            return {}
        declared = set(self.parameter_schema.model_fields)
        filtered = {
            key: value
            for key, value in action.parameters.custom.items()
            if key in declared
        }
        model = self.parameter_schema.model_validate(filtered)
        return model.model_dump(exclude_none=True)

    @staticmethod
    def _elapsed_ms(started: float) -> float:
        return (time.perf_counter() - started) * 1000.0
