"""Simulated containment executor — the safe default.

Maintains an in-memory ledger of "active containments" so the platform is
functional end to end (a blocked IP really does appear blocked to the rest of
the system) while producing no side-effect outside this process.

This is the executor the platform ships with. Replacing it with a real
firewall or EDR integration is a startup wiring change:

    registry.register(IptablesExecutor(), override=True)

Nothing in this module imports a network client, subprocess, or cloud SDK.
"""
from __future__ import annotations

import logging
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from adapters.response.base import (
    ExecutionReceipt,
    ExecutionRequest,
    PermanentExecutorError,
    ResponseExecutor,
)
from cyber_surakshya.platform.actions.action_type import ActionType

logger = logging.getLogger(__name__)

# Verbs this executor simulates, and their inverse for rollback.
_INVERSE_ACTIONS: dict[ActionType, ActionType] = {
    ActionType.BLOCK_IP:     ActionType.UNBLOCK_IP,
    ActionType.UNBLOCK_IP:   ActionType.BLOCK_IP,
    ActionType.ISOLATE_HOST: ActionType.RELEASE_HOST,
    ActionType.RELEASE_HOST: ActionType.ISOLATE_HOST,
}


@dataclass
class ContainmentEntry:
    """One active simulated containment."""

    entry_id:     str
    action_type:  ActionType
    target_type:  str
    target_value: str
    created_at:   datetime
    expires_at:   datetime | None = None
    reverted:     bool            = False
    details:      dict[str, Any]  = field(default_factory=dict)

    def is_active(self, now: datetime | None = None) -> bool:
        """Return True when this containment is still in force."""
        if self.reverted:
            return False
        if self.expires_at is None:
            return True
        return (now or datetime.now(timezone.utc)) < self.expires_at


class SimulatedContainmentExecutor(ResponseExecutor):
    """Records containment actions in an in-memory ledger.

    Thread-safe: FastAPI serves requests from a thread pool, so the ledger is
    guarded by a lock rather than relying on GIL atomicity.
    """

    executor_name    = "SimulatedContainmentExecutor"
    executor_version = "1.0.0"
    # Each verb is routable only for the target types it is meaningful for.
    # ISOLATE_HOST accepts both IP and HOST: at the network layer a host is
    # identified by address, at the endpoint layer by hostname. A future EDR
    # executor claims ("ISOLATE_HOST", "HOST") with override=True.
    action_targets = {
        ActionType.BLOCK_IP:           frozenset({"IP"}),
        ActionType.UNBLOCK_IP:         frozenset({"IP"}),
        ActionType.ISOLATE_HOST:       frozenset({"IP", "HOST"}),
        ActionType.RELEASE_HOST:       frozenset({"IP", "HOST"}),
        ActionType.RATE_LIMIT:         frozenset({"IP", "HOST", "ENDPOINT"}),
        ActionType.QUARANTINE_FILE:    frozenset({"FILE"}),
        ActionType.TERMINATE_PROCESS:  frozenset({"PROCESS"}),
        ActionType.REVOKE_CREDENTIALS: frozenset({"USER", "ACCOUNT"}),
    }

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._ledger: dict[str, ContainmentEntry] = {}

    # ── Execution ─────────────────────────────────────────────────────────────

    def execute(self, request: ExecutionRequest) -> ExecutionReceipt:
        """Record the containment and return a revertable receipt."""
        action = request.action
        target = action.target

        if request.dry_run:
            logger.info(
                "simulated_executor_dry_run",
                extra={
                    "action_type": action.action_type.value,
                    "target":      target.target_value,
                    "decision_id": request.decision_id,
                },
            )
            return ExecutionReceipt(
                succeeded=True,
                executor_name=self.executor_name,
                executor_version=self.executor_version,
                details={"dry_run": True, "ledger_written": False},
            )

        duration = action.parameters.duration_seconds
        now      = datetime.now(timezone.utc)
        expires  = now + timedelta(seconds=duration) if duration else None
        entry_id = str(uuid.uuid4())

        entry = ContainmentEntry(
            entry_id=entry_id,
            action_type=action.action_type,
            target_type=target.target_type.upper(),
            target_value=target.target_value,
            created_at=now,
            expires_at=expires,
            details={
                "scope":       action.parameters.scope,
                "decision_id": request.decision_id,
            },
        )
        with self._lock:
            self._ledger[entry_id] = entry
            # An inverse action clears any matching active containment, so the
            # simulated world stays coherent (UNBLOCK_IP really does unblock).
            self._apply_inverse_locked(entry)

        logger.info(
            "simulated_executor_executed",
            extra={
                "action_type":    action.action_type.value,
                "target":         target.target_value,
                "entry_id":       entry_id,
                "expires_at":     expires.isoformat() if expires else None,
                "correlation_id": request.correlation_id,
            },
        )
        return ExecutionReceipt(
            succeeded=True,
            executor_name=self.executor_name,
            executor_version=self.executor_version,
            external_reference=entry_id,
            revert_token=entry_id,
            expires_at=expires,
            details={
                "ledger_written": True,
                "target_type":    entry.target_type,
                "target_value":   entry.target_value,
                "action_type":    action.action_type.value,
            },
        )

    def revert(self, receipt: ExecutionReceipt) -> ExecutionReceipt:
        """Clear a previously recorded containment."""
        token = receipt.revert_token
        if not token:
            raise PermanentExecutorError(
                "Cannot revert a receipt with no revert_token."
            )
        with self._lock:
            entry = self._ledger.get(token)
            if entry is None:
                raise PermanentExecutorError(
                    f"No containment ledger entry for revert token {token!r}."
                )
            if entry.reverted:
                logger.info(
                    "simulated_executor_revert_noop",
                    extra={"entry_id": token},
                )
            entry.reverted = True

        logger.info(
            "simulated_executor_reverted",
            extra={"entry_id": token, "action_type": entry.action_type.value},
        )
        return ExecutionReceipt(
            succeeded=True,
            executor_name=self.executor_name,
            executor_version=self.executor_version,
            external_reference=token,
            revert_token=None,
            details={
                "reverted":     True,
                "action_type":  entry.action_type.value,
                "target_value": entry.target_value,
            },
        )

    # ── Ledger inspection (diagnostics; not the API read model) ──────────────

    def active_entries(self) -> tuple[ContainmentEntry, ...]:
        """Return currently-active containments."""
        now = datetime.now(timezone.utc)
        with self._lock:
            return tuple(e for e in self._ledger.values() if e.is_active(now))

    def is_contained(self, target_value: str, action_type: ActionType) -> bool:
        """Return True when a target currently has an active containment."""
        now = datetime.now(timezone.utc)
        with self._lock:
            return any(
                e.target_value == target_value
                and e.action_type is action_type
                and e.is_active(now)
                for e in self._ledger.values()
            )

    # ── Private ───────────────────────────────────────────────────────────────

    def _apply_inverse_locked(self, entry: ContainmentEntry) -> None:
        """Retire active containments that this action inverts.

        Caller must hold the lock.
        """
        inverse = _INVERSE_ACTIONS.get(entry.action_type)
        if inverse is None:
            return
        for existing in self._ledger.values():
            if (
                existing.entry_id != entry.entry_id
                and existing.action_type is inverse
                and existing.target_value == entry.target_value
                and not existing.reverted
            ):
                existing.reverted = True
