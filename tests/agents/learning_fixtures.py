"""Shared fixtures for LearningAgent tests.

Provides a fake MemoryProvider and builders for the memory payloads the
pipeline agents actually write, so the tests exercise the real join logic
rather than a mocked one.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from memory.models import MemoryQuery, MemoryRecord, MemorySearchResult

BASE_TIME = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)


def new_id() -> str:
    return str(uuid.uuid4())


class FakeMemoryProvider:
    """In-memory MemoryProvider honouring the query filters the agent uses."""

    def __init__(self, *, fail_collections: set[str] | None = None) -> None:
        self.collections: dict[str, list[MemoryRecord]] = {}
        self.fail_collections = fail_collections or set()

    def store(self, collection: str, record: MemoryRecord) -> MemoryRecord:
        if collection in self.fail_collections:
            raise RuntimeError(f"simulated storage failure for {collection!r}")
        self.collections.setdefault(collection, []).append(record)
        return record

    def search(self, collection: str, query: MemoryQuery) -> list[MemorySearchResult]:
        if collection in self.fail_collections:
            raise RuntimeError(f"simulated read failure for {collection!r}")
        records = list(self.collections.get(collection, []))

        if query.record_types:
            records = [r for r in records if r.record_type in query.record_types]
        if query.entity_ids:
            records = [r for r in records if r.entity_id in query.entity_ids]
        if query.created_after:
            records = [r for r in records if r.created_at >= query.created_after]

        records.sort(key=lambda r: r.created_at, reverse=query.descending)
        if query.limit:
            records = records[: query.limit]
        return [MemorySearchResult(record=r, score=1.0) for r in records]

    def get(self, collection, record_id):        # pragma: no cover - unused
        return None

    def update(self, collection, record):        # pragma: no cover - unused
        return record

    def delete(self, collection, record_id):     # pragma: no cover - unused
        return False

    def exists(self, collection, record_id):     # pragma: no cover - unused
        return False


# ── Record builders (mirror what the pipeline agents write) ───────────────────


def detection_record(
    *,
    detection_id: str | None = None,
    predicted_label: str = "DDOS",
    status: str = "detected",
    confidence: float = 0.95,
    entity_id: str = "203.0.113.10",
    correlation_id: str | None = None,
    observed_at: datetime | None = BASE_TIME,
    detect_seconds: float = 2.0,
    created_at: datetime | None = None,
) -> MemoryRecord:
    detection_id = detection_id or new_id()
    content: dict[str, Any] = {
        "event_id":        new_id(),
        "detection_id":    detection_id,
        "predicted_label": predicted_label,
        "confidence":      confidence,
        "status":          status,
    }
    if observed_at is not None:
        content["observed_at"] = observed_at.isoformat()
        content["detected_at"] = (observed_at + timedelta(seconds=detect_seconds)).isoformat()
    return MemoryRecord(
        backend="test",
        collection="detections",
        record_type="detection_result",
        entity_id=entity_id,
        correlation_id=correlation_id or new_id(),
        content=content,
        created_at=created_at or BASE_TIME,
    )


def analysis_record(detection_id: str, *, created_at: datetime | None = None) -> MemoryRecord:
    return MemoryRecord(
        backend="test",
        collection="analysis",
        record_type="analysis_result",
        content={
            "analysis_id":  new_id(),
            "detection_id": detection_id,
            "summary":      "test",
            "confidence":   0.9,
        },
        created_at=created_at or BASE_TIME,
    )


def decision_record(
    detection_id: str,
    *,
    decision_id: str | None = None,
    action_type: str = "BLOCK_IP",
    policy_name: str = "critical_high_risk_auto_block",
    decision_engine: str = "DeterministicDecisionEngine",
    created_at: datetime | None = None,
) -> MemoryRecord:
    return MemoryRecord(
        backend="test",
        collection="decisions",
        record_type="decision_result",
        content={
            "decision_id":     decision_id or new_id(),
            "detection_id":    detection_id,
            "action_type":     action_type,
            "policy_name":     policy_name,
            "decision_engine": decision_engine,
            "priority":        "CRITICAL",
        },
        created_at=created_at or BASE_TIME,
    )


def response_record(
    decision_id: str,
    *,
    status: str = "EXECUTED",
    action_type: str = "BLOCK_IP",
    target_value: str = "203.0.113.10",
    executor_name: str = "SimulatedContainmentExecutor",
    decision_engine: str = "DeterministicDecisionEngine",
    guard_rule: str = "authorised",
    observed_at: datetime | None = BASE_TIME,
    respond_seconds: float = 5.0,
    created_at: datetime | None = None,
) -> MemoryRecord:
    content: dict[str, Any] = {
        "response_id":       new_id(),
        "decision_id":       decision_id,
        "status":            status,
        "action_type":       action_type,
        "target_value":      target_value,
        "executor_name":     executor_name,
        "decision_engine":   decision_engine,
        "guard_rule":        guard_rule,
    }
    if observed_at is not None:
        content["executed_at"] = (observed_at + timedelta(seconds=respond_seconds)).isoformat()
    return MemoryRecord(
        backend="test",
        collection="responses",
        record_type="response_result",
        content=content,
        created_at=created_at or BASE_TIME,
    )


def approval_record(decision_id: str, *, approved: bool = True) -> MemoryRecord:
    return MemoryRecord(
        backend="test",
        collection="approvals",
        record_type="response_approval",
        entity_id=decision_id,
        content={
            "decision_id": decision_id,
            "approved":    approved,
            "approved_by": "analyst@soc",
            "reason":      None,
        },
        created_at=BASE_TIME,
    )


def seed_incident(
    memory: FakeMemoryProvider,
    *,
    predicted_label: str = "DDOS",
    status: str = "detected",
    entity_id: str = "203.0.113.10",
    action_type: str = "BLOCK_IP",
    response_status: str | None = "EXECUTED",
    approved: bool | None = None,
    observed_at: datetime | None = BASE_TIME,
    detect_seconds: float = 2.0,
    respond_seconds: float = 5.0,
    confidence: float = 0.95,
    decision_engine: str = "DeterministicDecisionEngine",
    guard_rule: str = "authorised",
    with_analysis: bool = True,
    with_decision: bool = True,
) -> str:
    """Seed one full (or partial) incident. Returns its detection_id."""
    detection = detection_record(
        predicted_label=predicted_label,
        status=status,
        entity_id=entity_id,
        confidence=confidence,
        observed_at=observed_at,
        detect_seconds=detect_seconds,
    )
    detection_id = detection.content["detection_id"]
    memory.store("detections", detection)

    if not with_analysis:
        return detection_id
    memory.store("analysis", analysis_record(detection_id))

    if not with_decision:
        return detection_id
    decision = decision_record(
        detection_id, action_type=action_type, decision_engine=decision_engine
    )
    decision_id = decision.content["decision_id"]
    memory.store("decisions", decision)

    if response_status is not None:
        memory.store(
            "responses",
            response_record(
                decision_id,
                status=response_status,
                action_type=action_type,
                target_value=entity_id,
                decision_engine=decision_engine,
                guard_rule=guard_rule,
                observed_at=observed_at,
                respond_seconds=respond_seconds,
            ),
        )
    if approved is not None:
        memory.store("approvals", approval_record(decision_id, approved=approved))

    return detection_id
