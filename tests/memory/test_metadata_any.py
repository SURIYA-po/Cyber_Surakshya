"""Contract tests for MemoryQuery.metadata_any, run against every provider.

The filter exists so a page of parent records can be joined to its children in
one query instead of one per parent. Both providers are exercised through the
same cases because the predicate is shared — a divergence here would silently
change what a read model joins to.
"""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from memory.inmemory import InMemoryMemoryProvider
from memory.models import MemoryQuery, MemoryRecord
from memory.qdrant_sqlite import QdrantSqliteMemoryProvider

BASE = datetime(2026, 8, 1, tzinfo=timezone.utc)


@pytest.fixture(params=["inmemory", "qdrant_sqlite"])
def provider(request):
    if request.param == "inmemory":
        yield InMemoryMemoryProvider()
        return
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_meta.db")
        with QdrantSqliteMemoryProvider(db_path=db_path, qdrant_path=":memory:") as p:
            yield p


def store(provider, *, detection_id=None, agent=None, minutes=0, extra=None):
    metadata = dict(extra or {})
    if detection_id is not None:
        metadata["detection_id"] = detection_id
    if agent is not None:
        metadata["agent"] = agent
    record = MemoryRecord(
        collection="analysis",
        record_type="analysis_result",
        entity_id="10.0.0.1",
        content={"note": detection_id},
        metadata=metadata,
        created_at=BASE + timedelta(minutes=minutes),
    )
    provider.store("analysis", record)
    return record


def ids(results):
    return {hit.record.content["note"] for hit in results}


# ── Matching ─────────────────────────────────────────────────────────────────


def test_single_key_single_value(provider):
    store(provider, detection_id="det-1")
    store(provider, detection_id="det-2")

    results = provider.search(
        "analysis", MemoryQuery(metadata_any={"detection_id": ["det-1"]})
    )
    assert ids(results) == {"det-1"}


def test_single_key_multiple_values_are_ored(provider):
    store(provider, detection_id="det-1")
    store(provider, detection_id="det-2")
    store(provider, detection_id="det-3")

    results = provider.search(
        "analysis", MemoryQuery(metadata_any={"detection_id": ["det-1", "det-3"]})
    )
    assert ids(results) == {"det-1", "det-3"}


def test_multiple_keys_are_anded(provider):
    store(provider, detection_id="det-1", agent="analysis_agent")
    store(provider, detection_id="det-2", agent="other_agent")

    results = provider.search(
        "analysis",
        MemoryQuery(
            metadata_any={
                "detection_id": ["det-1", "det-2"],
                "agent": ["analysis_agent"],
            }
        ),
    )
    assert ids(results) == {"det-1"}


def test_no_match_returns_empty(provider):
    store(provider, detection_id="det-1")

    results = provider.search(
        "analysis", MemoryQuery(metadata_any={"detection_id": ["det-999"]})
    )
    assert results == []


def test_absent_key_never_matches(provider):
    """Presence is required — this is exact matching, not a null-tolerant join."""
    store(provider, agent="analysis_agent")  # no detection_id at all

    results = provider.search(
        "analysis", MemoryQuery(metadata_any={"detection_id": [None, "det-1"]})
    )
    assert results == []


def test_combined_with_exact_metadata_filter(provider):
    store(provider, detection_id="det-1", agent="analysis_agent")
    store(provider, detection_id="det-2", agent="analysis_agent")

    results = provider.search(
        "analysis",
        MemoryQuery(
            metadata={"agent": "analysis_agent"},
            metadata_any={"detection_id": ["det-2"]},
        ),
    )
    assert ids(results) == {"det-2"}


# ── Ordering and limit ───────────────────────────────────────────────────────


def test_limit_applies_after_filtering_descending(provider):
    """`limit` must bound the matching rows, not the rows that were read.

    Read models depend on this: a page of children must not be truncated by
    rows that were never going to match the join key.
    """
    store(provider, detection_id="other", minutes=50)
    store(provider, detection_id="det-1", minutes=10)
    store(provider, detection_id="det-2", minutes=20)
    store(provider, detection_id="det-3", minutes=30)
    store(provider, detection_id="other", minutes=60)

    results = provider.search(
        "analysis",
        MemoryQuery(
            metadata_any={"detection_id": ["det-1", "det-2", "det-3"]},
            order_by="created_at",
            descending=True,
            limit=2,
        ),
    )
    assert ids(results) == {"det-3", "det-2"}


def test_limit_applies_after_filtering_ascending(provider):
    store(provider, detection_id="other", minutes=50)
    store(provider, detection_id="det-1", minutes=10)
    store(provider, detection_id="det-2", minutes=20)
    store(provider, detection_id="det-3", minutes=30)

    results = provider.search(
        "analysis",
        MemoryQuery(
            metadata_any={"detection_id": ["det-1", "det-2", "det-3"]},
            order_by="created_at",
            descending=False,
            limit=2,
        ),
    )
    assert ids(results) == {"det-1", "det-2"}


def test_ordering_is_preserved_under_filtering(provider):
    store(provider, detection_id="det-1", minutes=10)
    store(provider, detection_id="det-2", minutes=20)
    store(provider, detection_id="det-3", minutes=30)

    query = MemoryQuery(
        metadata_any={"detection_id": ["det-1", "det-2", "det-3"]},
        order_by="created_at",
        descending=True,
    )
    ordered = [hit.record.content["note"] for hit in provider.search("analysis", query)]
    assert ordered == ["det-3", "det-2", "det-1"]


# ── Backward compatibility ───────────────────────────────────────────────────


def test_omitting_metadata_any_changes_nothing(provider):
    store(provider, detection_id="det-1", agent="analysis_agent")
    store(provider, detection_id="det-2", agent="other_agent")

    assert len(provider.search("analysis", MemoryQuery())) == 2
    assert len(
        provider.search("analysis", MemoryQuery(metadata_any=None))
    ) == 2
    # The pre-existing exact filter is untouched.
    results = provider.search(
        "analysis", MemoryQuery(metadata={"agent": "analysis_agent"})
    )
    assert ids(results) == {"det-1"}


# ── Validation ───────────────────────────────────────────────────────────────


def test_empty_alternative_list_is_rejected():
    """Matches nothing — nearly always an accidentally-empty parent page."""
    with pytest.raises(ValidationError):
        MemoryQuery(metadata_any={"detection_id": []})


def test_non_list_alternatives_are_rejected():
    with pytest.raises(ValidationError):
        MemoryQuery(metadata_any={"detection_id": "det-1"})


def test_blank_key_is_rejected():
    with pytest.raises(ValidationError):
        MemoryQuery(metadata_any={"  ": ["det-1"]})


def test_matches_metadata_is_the_shared_predicate():
    """Both providers call this, so it is the contract they share."""
    query = MemoryQuery(metadata_any={"detection_id": ["det-1", "det-2"]})
    assert query.matches_metadata({"detection_id": "det-1"}) is True
    assert query.matches_metadata({"detection_id": "det-9"}) is False
    assert query.matches_metadata({}) is False
    assert query.matches_metadata(None) is False
    assert MemoryQuery().matches_metadata({"anything": 1}) is True
