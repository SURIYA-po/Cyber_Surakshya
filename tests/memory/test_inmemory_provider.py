"""Tests for the in-memory memory provider."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

from cyber_surakshya.platform.identifiers.correlation import CorrelationContext
from memory import (
    InMemoryMemoryProvider,
    MemoryQuery,
    MemoryRecord,
    MemoryRecordAlreadyExistsError,
    MemoryRecordNotFoundError,
)


def make_record(
    *,
    record_type: str = "security_event",
    entity_id: str = "entity-1",
    collection: str = "custom",
    metadata: dict[str, object] | None = None,
    tags: list[str] | None = None,
    created_at: datetime | None = None,
) -> MemoryRecord:
    ctx = CorrelationContext.create()
    return MemoryRecord(
        collection=collection,
        record_type=record_type,
        entity_id=entity_id,
        correlation_id=ctx.correlation_id,
        trace_id=ctx.trace_id,
        content={"message": "stored fact"},
        metadata=metadata or {},
        tags=tags or [],
        created_at=created_at or datetime.now(timezone.utc),
    )


def test_store_get_exists_and_backend_collection_stamping():
    provider = InMemoryMemoryProvider()
    record = make_record(collection="wrong", metadata={"severity": "high"})

    stored = provider.store("security_events", record)

    assert stored.backend == "memory"
    assert stored.collection == "security_events"
    assert provider.exists("security_events", stored.record_id) is True
    assert provider.get("security_events", stored.record_id) == stored
    assert provider.exists("detections", stored.record_id) is False


def test_store_rejects_duplicate_record_in_same_collection():
    provider = InMemoryMemoryProvider()
    record = make_record()

    stored = provider.store("analysis", record)

    with pytest.raises(MemoryRecordAlreadyExistsError):
        provider.store("analysis", stored)


def test_same_record_id_can_exist_in_different_collections():
    provider = InMemoryMemoryProvider()
    record = make_record()

    first = provider.store("analysis", record)
    second = provider.store("detections", record)

    assert first.record_id == second.record_id
    assert first.collection == "analysis"
    assert second.collection == "detections"


def test_update_existing_record_preserves_created_at_and_changes_content():
    provider = InMemoryMemoryProvider()
    stored = provider.store("analysis", make_record(metadata={"version": 1}))
    updated_record = stored.model_copy(
        update={
            "content": {"message": "updated fact"},
            "metadata": {"version": 2},
        }
    )

    updated = provider.update("analysis", updated_record)

    assert updated.record_id == stored.record_id
    assert updated.created_at == stored.created_at
    assert updated.updated_at >= stored.updated_at
    assert updated.content == {"message": "updated fact"}
    assert updated.metadata == {"version": 2}


def test_update_missing_record_raises():
    provider = InMemoryMemoryProvider()

    with pytest.raises(MemoryRecordNotFoundError):
        provider.update("analysis", make_record())


def test_delete_existing_and_missing_record():
    provider = InMemoryMemoryProvider()
    stored = provider.store("analysis", make_record())

    assert provider.delete("analysis", stored.record_id) is True
    assert provider.get("analysis", stored.record_id) is None
    assert provider.delete("analysis", stored.record_id) is False


def test_search_filters_by_record_type_entity_correlation_and_trace():
    provider = InMemoryMemoryProvider()
    event = provider.store("security_events", make_record(record_type="event"))
    provider.store("security_events", make_record(record_type="event", entity_id="other"))
    provider.store("security_events", make_record(record_type="analysis"))

    results = provider.search(
        "security_events",
        MemoryQuery(
            record_types=["event"],
            entity_ids=[event.entity_id],
            correlation_id=event.correlation_id,
            trace_id=event.trace_id,
        ),
    )

    assert [result.record.record_id for result in results] == [event.record_id]


def test_search_filters_by_metadata_subset_and_tags():
    provider = InMemoryMemoryProvider()
    matched = provider.store(
        "analysis",
        make_record(
            metadata={"severity": "high", "source": "ids"},
            tags=["review", "network"],
        ),
    )
    provider.store(
        "analysis",
        make_record(metadata={"severity": "low"}, tags=["network"]),
    )

    results = provider.search(
        "analysis",
        MemoryQuery(metadata={"severity": "high"}, tags=["review"]),
    )

    assert [result.record.record_id for result in results] == [matched.record_id]


def test_search_orders_by_time_and_applies_limit():
    provider = InMemoryMemoryProvider()
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    oldest = provider.store("learning", make_record(created_at=base))
    middle = provider.store("learning", make_record(created_at=base + timedelta(days=1)))
    newest = provider.store("learning", make_record(created_at=base + timedelta(days=2)))

    descending = provider.search(
        "learning",
        MemoryQuery(order_by="created_at", descending=True, limit=2),
    )
    ascending = provider.search("learning", MemoryQuery(order_by="created_at"))

    assert [result.record.record_id for result in descending] == [
        newest.record_id,
        middle.record_id,
    ]
    assert [result.record.record_id for result in ascending] == [
        oldest.record_id,
        middle.record_id,
        newest.record_id,
    ]


def test_search_filters_by_time_window():
    provider = InMemoryMemoryProvider()
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    provider.store("incidents", make_record(created_at=base))
    matched = provider.store("incidents", make_record(created_at=base + timedelta(hours=2)))
    provider.store("incidents", make_record(created_at=base + timedelta(hours=4)))

    results = provider.search(
        "incidents",
        MemoryQuery(
            created_after=base + timedelta(hours=1),
            created_before=base + timedelta(hours=3),
        ),
    )

    assert [result.record.record_id for result in results] == [matched.record_id]


def test_returned_records_are_defensive_copies():
    provider = InMemoryMemoryProvider()
    stored = provider.store("custom", make_record())

    fetched = provider.get("custom", stored.record_id)
    assert fetched is not None
    fetched.content["message"] = "mutated"

    fetched_again = provider.get("custom", stored.record_id)
    assert fetched_again is not None
    assert fetched_again.content == {"message": "stored fact"}


def test_thread_safe_concurrent_stores_smoke():
    provider = InMemoryMemoryProvider()

    def store_one(index: int) -> str:
        record = make_record(entity_id=f"entity-{index}")
        return provider.store("conversations", record).record_id

    with ThreadPoolExecutor(max_workers=8) as executor:
        record_ids = list(executor.map(store_one, range(25)))

    results = provider.search("conversations", MemoryQuery())

    assert len(record_ids) == 25
    assert len({result.record.record_id for result in results}) == 25
