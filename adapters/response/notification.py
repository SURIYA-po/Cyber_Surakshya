"""Notification executor — SOC alerting, ticketing, and audit-only verbs.

Handles the non-destructive half of the action vocabulary. These are the
verbs an AI decision engine is permitted to trigger without human approval,
so this executor carries the traffic produced by the AI_SUPERVISED trust tier
(see agents/response/trust.py).

Notifications are appended to an in-process outbox rather than sent. Wiring a
real Slack/email/TheHive integration is a startup swap:

    registry.register(SlackNotificationExecutor(), override=True)

Nothing in this module performs network I/O.
"""
from __future__ import annotations

import logging
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from adapters.response.base import (
    ExecutionReceipt,
    ExecutionRequest,
    ResponseExecutor,
)
from cyber_surakshya.platform.actions.action_type import ActionType

logger = logging.getLogger(__name__)

# Maximum notifications retained in the outbox. Bounded so a runaway decision
# engine cannot exhaust memory through the one path it is always allowed.
_MAX_OUTBOX = 1000


@dataclass(frozen=True)
class Notification:
    """One dispatched notification."""

    notification_id: str
    action_type:     ActionType
    target_type:     str
    target_value:    str
    channel:         str
    created_at:      datetime
    details:         dict[str, Any]


class NotificationExecutor(ResponseExecutor):
    """Records SOC notifications, tickets, enrichment, and log-only actions."""

    executor_name    = "NotificationExecutor"
    executor_version = "1.0.0"
    # Notification verbs are target-agnostic: the SOC can be told about any
    # entity class, so every target type is routable for all four verbs.
    _ALL_TARGETS = frozenset({
        "IP", "HOST", "FILE", "PROCESS", "USER", "ACCOUNT", "ENDPOINT", "EVENT",
    })
    action_targets = {
        ActionType.NOTIFY_SOC:          _ALL_TARGETS,
        ActionType.OPEN_TICKET:         _ALL_TARGETS,
        ActionType.ENRICH_THREAT_INTEL: _ALL_TARGETS,
        ActionType.LOG_ONLY:            _ALL_TARGETS,
    }

    # Channel used for each verb. Real implementations map these to
    # transports; the simulated executor only records them.
    _CHANNELS: dict[ActionType, str] = {
        ActionType.NOTIFY_SOC:          "soc_queue",
        ActionType.OPEN_TICKET:         "ticketing",
        ActionType.ENRICH_THREAT_INTEL: "threat_intel",
        ActionType.LOG_ONLY:            "audit_log",
    }

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._outbox: list[Notification] = []

    def execute(self, request: ExecutionRequest) -> ExecutionReceipt:
        """Record a notification and return a receipt.

        Notifications are not revertable — ``revert_token`` is deliberately
        left unset so the platform cannot claim to have un-sent an alert.
        """
        action  = request.action
        channel = self._CHANNELS.get(action.action_type, "audit_log")

        if request.dry_run:
            logger.info(
                "notification_executor_dry_run",
                extra={
                    "action_type": action.action_type.value,
                    "channel":     channel,
                    "decision_id": request.decision_id,
                },
            )
            return ExecutionReceipt(
                succeeded=True,
                executor_name=self.executor_name,
                executor_version=self.executor_version,
                details={"dry_run": True, "channel": channel, "dispatched": False},
            )

        notification = Notification(
            notification_id=str(uuid.uuid4()),
            action_type=action.action_type,
            target_type=action.target.target_type.upper(),
            target_value=action.target.target_value,
            channel=channel,
            created_at=datetime.now(timezone.utc),
            details={
                "decision_id":    request.decision_id,
                "correlation_id": request.correlation_id,
                "scope":          action.parameters.scope,
            },
        )
        with self._lock:
            self._outbox.append(notification)
            if len(self._outbox) > _MAX_OUTBOX:
                del self._outbox[: len(self._outbox) - _MAX_OUTBOX]

        logger.info(
            "notification_executor_dispatched",
            extra={
                "action_type":     action.action_type.value,
                "channel":         channel,
                "notification_id": notification.notification_id,
                "target":          notification.target_value,
                "correlation_id":  request.correlation_id,
            },
        )
        return ExecutionReceipt(
            succeeded=True,
            executor_name=self.executor_name,
            executor_version=self.executor_version,
            external_reference=notification.notification_id,
            revert_token=None,
            details={
                "channel":      channel,
                "dispatched":   True,
                "target_value": notification.target_value,
                "action_type":  action.action_type.value,
            },
        )

    def notifications(self) -> tuple[Notification, ...]:
        """Return the notification outbox, newest last."""
        with self._lock:
            return tuple(self._outbox)
