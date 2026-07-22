"""Tests for QdrantSqliteMemoryProvider.

Imports are made directly from submodules (not from the `memory` package root)
to avoid triggering the lazy PostgreSQLMemoryProvider path that needs asyncpg.
"""

import concurrent.futures
import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

# Import directly from submodules – avoids the asyncpg dependency chain
from memory.exceptions import (
    MemoryRecordAlreadyExistsError,
    MemoryRecordNotFoundError,
)
from memory.models import MemoryQuery, MemoryRecord
from memory.qdrant_sqlite import QdrantSqliteMemoryProvider


# ---------------------------------------------------------------------------
# Shared fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def provider():
    """A fresh in-memory (Qdrant) + temp-file (SQLite) provider per test."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_meta.db")
        p = QdrantSqliteMemoryProvider(db_path=db_path, qdrant_path=":memory:")
        yield p


# ---------------------------------------------------------------------------
# CRUD tests
# ---------------------------------------------------------------------------

class TestCRUD:
    def test_store_creates_record(self, provider: QdrantSqliteMemoryProvider):
        record = MemoryRecord(collection="col", record_type="t", content="hello")
        returned = provider.store("col", record)
        assert returned.record_id == record.record_id
        assert returned.content == "hello"

    def test_get_returns_stored_record(self, provider: QdrantSqliteMemoryProvider):
        record = MemoryRecord(collection="col", record_type="t", content="hello")
        provider.store("col", record)
        fetched = provider.get("col", record.record_id)
        assert fetched is not None
        assert fetched.content == "hello"

    def test_get_unknown_id_returns_none(self, provider: QdrantSqliteMemoryProvider):
        result = provider.get("col", "00000000-0000-0000-0000-000000000000")
        assert result is None

    def test_exists(self, provider: QdrantSqliteMemoryProvider):
        record = MemoryRecord(collection="col", record_type="t", content="x")
        assert not provider.exists("col", record.record_id)
        provider.store("col", record)
        assert provider.exists("col", record.record_id)

    def test_duplicate_store_raises(self, provider: QdrantSqliteMemoryProvider):
        record = MemoryRecord(collection="col", record_type="t", content="x")
        provider.store("col", record)
        with pytest.raises(MemoryRecordAlreadyExistsError):
            provider.store("col", record)

    def test_update_changes_content(self, provider: QdrantSqliteMemoryProvider):
        record = MemoryRecord(collection="col", record_type="t", content="before")
        provider.store("col", record)
        record.content = "after"
        provider.update("col", record)
        fetched = provider.get("col", record.record_id)
        assert fetched.content == "after"

    def test_update_missing_raises(self, provider: QdrantSqliteMemoryProvider):
        record = MemoryRecord(collection="col", record_type="t", content="x")
        with pytest.raises(MemoryRecordNotFoundError):
            provider.update("col", record)

    def test_delete_removes_record(self, provider: QdrantSqliteMemoryProvider):
        record = MemoryRecord(collection="col", record_type="t", content="x")
        provider.store("col", record)
        assert provider.delete("col", record.record_id) is True
        assert not provider.exists("col", record.record_id)

    def test_delete_missing_returns_false(self, provider: QdrantSqliteMemoryProvider):
        assert provider.delete("col", "00000000-0000-0000-0000-000000000000") is False


# ---------------------------------------------------------------------------
# Vector similarity tests
# ---------------------------------------------------------------------------

class TestVectorSearch:
    def test_semantic_search_returns_ranked_results(self, provider: QdrantSqliteMemoryProvider):
        """Semantic search must rank the most relevant document highest."""
        records = [
            MemoryRecord(collection="v", record_type="doc",
                         content="The quick brown fox jumps over the lazy dog."),
            MemoryRecord(collection="v", record_type="doc",
                         content="Python is a general-purpose programming language."),
            MemoryRecord(collection="v", record_type="doc",
                         content="A fast animal leaped over a resting canine."),
        ]
        for r in records:
            provider.store("v", r)

        query = MemoryQuery(query_text="fast fox jumping over a lazy dog")
        results = provider.search("v", query)

        assert len(results) == 3
        # Both fox and 'fast animal' sentences are about the same event;
        # crucially the Python sentence must be ranked LAST.
        assert results[-1].record.content == "Python is a general-purpose programming language."
        # Scores must be descending
        scores = [r.score for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_vector_search_returns_correct_count(self, provider: QdrantSqliteMemoryProvider):
        for i in range(5):
            provider.store("v2", MemoryRecord(collection="v2", record_type="x",
                                              content=f"Document number {i}"))
        results = provider.search("v2", MemoryQuery(query_text="document"))
        assert len(results) == 5

    def test_empty_collection_returns_empty_list(self, provider: QdrantSqliteMemoryProvider):
        results = provider.search("empty_coll", MemoryQuery(query_text="anything"))
        assert results == []


# ---------------------------------------------------------------------------
# Time-window filtering (SQLite path – no query_text)
# ---------------------------------------------------------------------------

class TestTimeFiltering:
    def test_created_after_and_before_window(self, provider: QdrantSqliteMemoryProvider):
        now = datetime.now(timezone.utc)

        r1 = MemoryRecord(collection="t", record_type="x", content="old")
        r1.created_at = now - timedelta(days=10)

        r2 = MemoryRecord(collection="t", record_type="x", content="mid")
        r2.created_at = now - timedelta(days=5)

        r3 = MemoryRecord(collection="t", record_type="x", content="recent")
        r3.created_at = now - timedelta(days=1)

        for r in [r1, r2, r3]:
            provider.store("t", r)

        q = MemoryQuery(
            created_after=now - timedelta(days=7),
            created_before=now - timedelta(days=2),
        )
        res = provider.search("t", q)
        assert len(res) == 1
        assert res[0].record.content == "mid"

    def test_no_filter_returns_all(self, provider: QdrantSqliteMemoryProvider):
        for i in range(3):
            provider.store("tf", MemoryRecord(collection="tf", record_type="x",
                                              content=str(i)))
        res = provider.search("tf", MemoryQuery())
        assert len(res) == 3


# ---------------------------------------------------------------------------
# Concurrency (RLock) test
# ---------------------------------------------------------------------------

class TestConcurrency:
    def test_concurrent_writes_all_succeed(self, provider: QdrantSqliteMemoryProvider):
        """20 workers inserting 50 records must all succeed with no race conditions."""
        def insert(i: int):
            rec = MemoryRecord(collection="m", record_type="t", content=f"Item {i}")
            provider.store("m", rec)

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            futures = [ex.submit(insert, i) for i in range(50)]
            for f in futures:
                f.result()  # raises if any thread threw

        res = provider.search("m", MemoryQuery(limit=100))
        assert len(res) == 50
