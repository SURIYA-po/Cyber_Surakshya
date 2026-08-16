"""Approval store — human authorisation that outlives a graph run.

A run that ends in AWAITING_APPROVAL terminates; the analyst approves minutes
or hours later. PlatformSharedState is a frozen snapshot of one execution and
cannot carry that, and its list fields use append reducers so a decision
cannot be retroactively marked approved in place.

Approvals therefore live outside graph state, in the memory layer, and are
read live at execution time. This is the branch that will justify a
CoordinatorAgent: it is the platform's first genuinely asynchronous edge.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol, runtime_checkable

from memory.base import MemoryProvider
from memory.models import MemoryQuery, MemoryRecord

logger = logging.getLogger(__name__)

APPROVAL_COLLECTION = "approvals"
_RECORD_TYPE = "response_approval"


@dataclass(frozen=True)
class ApprovalDecision:
    """An analyst's ruling on one decision."""

    decision_id: str
    approved:    bool
    approved_by: str
    reason:      str | None = None
    recorded_at: datetime | None = None


@runtime_checkable
class ApprovalStore(Protocol):
    """Port for reading and writing human approvals."""

    def approve(self, decision_id: str, *, approved_by: str, reason: str | None = None) -> ApprovalDecision:
        """Record analyst approval for a decision."""

    def reject(self, decision_id: str, *, approved_by: str, reason: str | None = None) -> ApprovalDecision:
        """Record analyst rejection for a decision."""

    def get(self, decision_id: str) -> ApprovalDecision | None:
        """Return the ruling for a decision, or None when undecided."""


class InMemoryApprovalStore:
    """Process-local approval store.

    Used in tests and as the fallback when no MemoryProvider is available.
    Approvals do not survive a restart, which is the safe direction: a lost
    approval blocks an action rather than authorising one.
    """

    def __init__(self) -> None:
        self._decisions: dict[str, ApprovalDecision] = {}

    def approve(self, decision_id: str, *, approved_by: str, reason: str | None = None) -> ApprovalDecision:
        return self._record(decision_id, True, approved_by, reason)

    def reject(self, decision_id: str, *, approved_by: str, reason: str | None = None) -> ApprovalDecision:
        return self._record(decision_id, False, approved_by, reason)

    def get(self, decision_id: str) -> ApprovalDecision | None:
        return self._decisions.get(decision_id)

    def _record(
        self,
        decision_id: str,
        approved: bool,
        approved_by: str,
        reason: str | None,
    ) -> ApprovalDecision:
        decision = ApprovalDecision(
            decision_id=decision_id,
            approved=approved,
            approved_by=approved_by,
            reason=reason,
            recorded_at=datetime.now(timezone.utc),
        )
        self._decisions[decision_id] = decision
        return decision


class MemoryApprovalStore:
    """Approval store backed by the platform MemoryProvider.

    Approvals are written as ordinary MemoryRecords in the ``approvals``
    collection, so they inherit the same persistence, querying, and audit
    surface as every other platform record.
    """

    def __init__(self, memory_provider: MemoryProvider) -> None:
        self.memory_provider = memory_provider

    def approve(self, decision_id: str, *, approved_by: str, reason: str | None = None) -> ApprovalDecision:
        return self._record(decision_id, True, approved_by, reason)

    def reject(self, decision_id: str, *, approved_by: str, reason: str | None = None) -> ApprovalDecision:
        return self._record(decision_id, False, approved_by, reason)

    def get(self, decision_id: str) -> ApprovalDecision | None:
        """Return the most recent ruling for a decision.

        A query failure returns None — "undecided" — so a memory outage
        blocks execution rather than allowing it.
        """
        try:
            hits = self.memory_provider.search(
                APPROVAL_COLLECTION,
                MemoryQuery(
                    record_types=[_RECORD_TYPE],
                    entity_ids=[decision_id],
                    order_by="created_at",
                    descending=True,
                    limit=1,
                ),
            )
        except Exception as exc:
            logger.warning(
                "response_approval_lookup_failed",
                extra={"decision_id": decision_id, "error": str(exc)},
            )
            return None

        if not hits:
            return None

        record  = hits[0].record
        content = record.content if isinstance(record.content, dict) else {}
        return ApprovalDecision(
            decision_id=decision_id,
            approved=bool(content.get("approved", False)),
            approved_by=str(content.get("approved_by", "unknown")),
            reason=content.get("reason"),
            recorded_at=record.created_at,
        )

    def _record(
        self,
        decision_id: str,
        approved: bool,
        approved_by: str,
        reason: str | None,
    ) -> ApprovalDecision:
        decision = ApprovalDecision(
            decision_id=decision_id,
            approved=approved,
            approved_by=approved_by,
            reason=reason,
            recorded_at=datetime.now(timezone.utc),
        )
        record = MemoryRecord(
            backend="qdrant_sqlite",
            collection=APPROVAL_COLLECTION,
            record_type=_RECORD_TYPE,
            entity_id=decision_id,
            content={
                "decision_id": decision_id,
                "approved":    approved,
                "approved_by": approved_by,
                "reason":      reason,
            },
            metadata={"agent": "response_agent"},
            tags=["response_agent", "approval",
                  "approved" if approved else "rejected"],
        )
        self.memory_provider.store(APPROVAL_COLLECTION, record)
        logger.info(
            "response_approval_recorded",
            extra={
                "decision_id": decision_id,
                "approved":    approved,
                "approved_by": approved_by,
            },
        )
        return decision
