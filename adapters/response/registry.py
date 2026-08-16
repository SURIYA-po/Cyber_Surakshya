"""Executor registry — routes an action to the integration that can perform it.

Resolution is keyed by ``(ActionType, target_type)`` rather than ActionType
alone, because the same verb means different things at different layers:
ISOLATE_HOST on an "IP" target is a network-perimeter action, while on a
"HOST" target it is an endpoint (EDR) action. When host and application-layer
adapters arrive they claim their own (verb, target) pairs without disturbing
the network executors already registered.
"""
from __future__ import annotations

import logging

from adapters.response.base import ResponseExecutor
from cyber_surakshya.platform.actions.action_type import ActionType

logger = logging.getLogger(__name__)


class MissingExecutorError(LookupError):
    """Raised when no registered executor can perform an action.

    This is a configuration gap, not a security failure — the decision was
    valid but the platform has no integration wired for it.
    """


class DuplicateExecutorError(ValueError):
    """Raised when two executors claim the same (action_type, target_type)."""


class ExecutorRegistry:
    """Registry of response executors, resolved by action and target type."""

    def __init__(self) -> None:
        self._executors: dict[tuple[ActionType, str], ResponseExecutor] = {}
        self._registered: list[ResponseExecutor] = []

    def register(self, executor: ResponseExecutor, *, override: bool = False) -> None:
        """Register an executor for every (action, target) pair it declares.

        Args:
            executor: the integration to register.
            override: replace an existing claim instead of raising. Intended
                for tests and for deliberately swapping a simulated executor
                for a real one at startup.

        Raises:
            ValueError: the executor declares no routable pairs.
            DuplicateExecutorError: a pair is already claimed.
        """
        if not executor.action_targets:
            raise ValueError(
                f"{executor.executor_name} declares no action_targets."
            )

        pairs = [
            (action, target.upper())
            for action, targets in executor.action_targets.items()
            for target in targets
        ]
        if not pairs:
            raise ValueError(
                f"{executor.executor_name} declares no target types for any action."
            )
        if not override:
            for pair in pairs:
                if pair in self._executors:
                    raise DuplicateExecutorError(
                        f"{pair[0].value} on target type {pair[1]!r} is already "
                        f"handled by {self._executors[pair].executor_name!r}. "
                        "Pass override=True to replace it."
                    )
        for pair in pairs:
            self._executors[pair] = executor

        self._registered.append(executor)
        logger.info(
            "response_executor_registered",
            extra={
                "executor":         executor.executor_name,
                "executor_version": executor.executor_version,
                "pairs":            len(pairs),
            },
        )

    def resolve(self, action_type: ActionType, target_type: str) -> ResponseExecutor:
        """Return the executor for a pair.

        Raises:
            MissingExecutorError: no executor claims the pair.
        """
        executor = self._executors.get((action_type, target_type.upper()))
        if executor is None:
            raise MissingExecutorError(
                f"No executor registered for {action_type.value} on target type "
                f"{target_type.upper()!r}. Registered pairs: "
                f"{sorted((a.value, t) for a, t in self._executors)}"
            )
        return executor

    def can_resolve(self, action_type: ActionType, target_type: str) -> bool:
        """Return True when a pair has a registered executor."""
        return (action_type, target_type.upper()) in self._executors

    @property
    def executors(self) -> tuple[ResponseExecutor, ...]:
        """Registered executors, for diagnostics and health checks."""
        return tuple(self._registered)

    @property
    def supported_pairs(self) -> tuple[tuple[ActionType, str], ...]:
        """All routable (action_type, target_type) pairs."""
        return tuple(sorted(self._executors, key=lambda p: (p[0].value, p[1])))
