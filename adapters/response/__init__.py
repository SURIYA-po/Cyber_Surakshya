"""Response executor adapters — the platform's outbound edge.

Only simulation-safe executors ship. Real integrations (firewall, EDR, SOAR)
are separate approved components; see docs/response_agent.md.
"""
from __future__ import annotations

from adapters.response.base import (
    ExecutionReceipt,
    ExecutionRequest,
    ExecutorError,
    PermanentExecutorError,
    ResponseExecutor,
    RevertNotSupportedError,
    TransientExecutorError,
)
from adapters.response.notification import Notification, NotificationExecutor
from adapters.response.registry import (
    DuplicateExecutorError,
    ExecutorRegistry,
    MissingExecutorError,
)
from adapters.response.simulated import (
    ContainmentEntry,
    SimulatedContainmentExecutor,
)

__all__ = [
    "ContainmentEntry",
    "DuplicateExecutorError",
    "ExecutionReceipt",
    "ExecutionRequest",
    "ExecutorError",
    "ExecutorRegistry",
    "MissingExecutorError",
    "Notification",
    "NotificationExecutor",
    "PermanentExecutorError",
    "ResponseExecutor",
    "RevertNotSupportedError",
    "SimulatedContainmentExecutor",
    "TransientExecutorError",
    "build_default_registry",
]


def build_default_registry() -> ExecutorRegistry:
    """Return a registry wired with the shipped simulation-safe executors.

    This is what app.py uses at startup. A deployment that has approved a real
    integration registers it over the top with ``override=True``.
    """
    registry = ExecutorRegistry()
    registry.register(SimulatedContainmentExecutor())
    registry.register(NotificationExecutor())
    return registry
