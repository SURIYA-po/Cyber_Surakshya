"""Qdrant + SQLite local storage memory provider."""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime

from qdrant_client import QdrantClient
from qdrant_client.models import Distance, PointIdsList, PointStruct, VectorParams
from sentence_transformers import SentenceTransformer

from memory.base import MemoryProvider
from memory.exceptions import (
    MemoryError,
    MemoryRecordAlreadyExistsError,
    MemoryRecordNotFoundError,
)
from memory.models import MemoryQuery, MemoryRecord, MemorySearchResult


class QdrantSqliteMemoryProvider(MemoryProvider):
    """Memory provider backed by embedded Qdrant for vectors and SQLite for exact matches."""

    def __init__(self, db_path: str = "memory_metadata.db", qdrant_path: str = "qdrant_db"):
        self._db_path = db_path
        self._qdrant_path = qdrant_path
        self._lock = threading.RLock()
        
        try:
            self._encoder = SentenceTransformer("all-MiniLM-L6-v2")
            # Support both old and new sentence-transformers API
            if hasattr(self._encoder, 'get_embedding_dimension'):
                self._vector_size = self._encoder.get_embedding_dimension()
            else:
                self._vector_size = self._encoder.get_sentence_embedding_dimension()
        except Exception as e:
            raise MemoryError(f"Failed to load sentence transformer: {e}")

        try:
            if self._qdrant_path == ":memory:":
                self._qdrant = QdrantClient(location=":memory:")
            else:
                self._qdrant = QdrantClient(path=self._qdrant_path)
            self._init_sqlite()
        except Exception as e:
            raise MemoryError(f"Failed to initialize databases: {e}")

    # ── Connection handling ───────────────────────────────────────────────────

    @contextmanager
    def _connect(self):
        """Yield a SQLite connection and always close it.

        `with sqlite3.connect(path) as conn:` commits or rolls back on exit but
        does NOT close the connection — a well-known gotcha. Every call here
        used to leak an open handle, which on Windows keeps the database file
        locked: `TemporaryDirectory` cleanup then failed with
        `PermissionError: [WinError 32]`, producing 15 teardown errors across
        the memory test suite, and `QdrantClient.__del__` raised at interpreter
        shutdown for the same reason.
        """
        conn = sqlite3.connect(self._db_path)
        try:
            with conn:          # transaction scope: commit on success, rollback on error
                yield conn
        finally:
            conn.close()        # handle scope: always released

    def close(self) -> None:
        """Release the Qdrant client. Idempotent.

        SQLite connections are already per-operation and closed by `_connect`.
        """
        client = getattr(self, "_qdrant", None)
        if client is None:
            return
        try:
            client.close()
        except Exception:
            # Closing twice, or closing during interpreter shutdown, must not
            # raise — this is called from fixtures and `__exit__`.
            pass
        finally:
            self._qdrant = None

    def __enter__(self) -> QdrantSqliteMemoryProvider:
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def _init_sqlite(self):
        """Initialize the SQLite schema."""
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS memory_records (
                        record_id TEXT PRIMARY KEY,
                        collection TEXT NOT NULL,
                        backend TEXT NOT NULL,
                        record_type TEXT NOT NULL,
                        entity_id TEXT,
                        correlation_id TEXT,
                        trace_id TEXT,
                        content TEXT,
                        metadata TEXT,
                        tags TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_memory_coll ON memory_records(collection)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_memory_created ON memory_records(created_at)")

    def _ensure_qdrant_collection(self, collection: str):
        """Ensure a Qdrant collection exists before using it."""
        with self._lock:
            try:
                if not self._qdrant.collection_exists(collection_name=collection):
                    self._qdrant.create_collection(
                        collection_name=collection,
                        vectors_config=VectorParams(size=self._vector_size, distance=Distance.COSINE),
                    )
            except Exception as e:
                raise MemoryError(f"Failed to ensure Qdrant collection: {e}")

    def _serialize_record(self, record: MemoryRecord) -> tuple:
        return (
            record.record_id,
            record.collection,
            record.backend,
            record.record_type,
            record.entity_id,
            record.correlation_id,
            record.trace_id,
            json.dumps(record.content) if record.content is not None else None,
            json.dumps(record.metadata),
            json.dumps(record.tags),
            record.created_at.isoformat(),
            record.updated_at.isoformat(),
        )

    def _deserialize_record(self, row: tuple) -> MemoryRecord:
        return MemoryRecord(
            record_id=row[0],
            collection=row[1],
            backend=row[2],
            record_type=row[3],
            entity_id=row[4],
            correlation_id=row[5],
            trace_id=row[6],
            content=json.loads(row[7]) if row[7] is not None else None,
            metadata=json.loads(row[8]) if row[8] else {},
            tags=json.loads(row[9]) if row[9] else [],
            created_at=datetime.fromisoformat(row[10]),
            updated_at=datetime.fromisoformat(row[11]),
        )

    def store(self, collection: str, record: MemoryRecord) -> MemoryRecord:
        with self._lock:
            if self.exists(collection, record.record_id):
                raise MemoryRecordAlreadyExistsError(f"Record {record.record_id} exists.")
            
            self._ensure_qdrant_collection(collection)
            
            try:
                # Save to SQLite
                with self._connect() as conn:
                    conn.execute(
                        "INSERT INTO memory_records VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        self._serialize_record(record)
                    )
                
                # Save to Qdrant
                text_to_embed = ""
                if isinstance(record.content, str):
                    text_to_embed = record.content
                elif record.content is not None:
                    text_to_embed = json.dumps(record.content)
                    
                if text_to_embed:
                    vector = self._encoder.encode(text_to_embed).tolist()
                    self._qdrant.upsert(
                        collection_name=collection,
                        points=[PointStruct(id=record.record_id, vector=vector, payload={"record_id": record.record_id})]
                    )
            except sqlite3.Error as e:
                raise MemoryError(f"SQLite error: {e}")
            except Exception as e:
                raise MemoryError(f"Qdrant error: {e}")
                
            return record.model_copy(deep=True)

    def get(self, collection: str, record_id: str) -> MemoryRecord | None:
        with self._lock:
            try:
                with self._connect() as conn:
                    cursor = conn.execute(
                        "SELECT * FROM memory_records WHERE collection = ? AND record_id = ?",
                        (collection, record_id)
                    )
                    row = cursor.fetchone()
                    if row:
                        return self._deserialize_record(row)
                    return None
            except sqlite3.Error as e:
                raise MemoryError(f"SQLite error: {e}")

    def count(self, collection: str) -> int:
        """Return the exact number of records in a collection.

        A SQL COUNT rather than len(search(...)): search is bounded by
        MemoryQuery.limit, so counting its result reports the page size. That
        is how the dashboard came to display a permanent "Total Alerts: 100"
        while memory actually held 999 detections.
        """
        with self._lock:
            try:
                with self._connect() as conn:
                    cursor = conn.execute(
                        "SELECT COUNT(*) FROM memory_records WHERE collection = ?",
                        (collection,),
                    )
                    row = cursor.fetchone()
                    return int(row[0]) if row else 0
            except sqlite3.Error as e:
                raise MemoryError(f"SQLite error: {e}")

    def update(self, collection: str, record: MemoryRecord) -> MemoryRecord:
        with self._lock:
            if not self.exists(collection, record.record_id):
                raise MemoryRecordNotFoundError(f"Record {record.record_id} not found.")
            
            self._ensure_qdrant_collection(collection)
            
            try:
                with self._connect() as conn:
                    conn.execute(
                        """
                        UPDATE memory_records SET 
                            backend = ?, record_type = ?, entity_id = ?, correlation_id = ?, 
                            trace_id = ?, content = ?, metadata = ?, tags = ?, 
                            created_at = ?, updated_at = ?
                        WHERE collection = ? AND record_id = ?
                        """,
                        (
                            record.backend, record.record_type, record.entity_id, 
                            record.correlation_id, record.trace_id,
                            json.dumps(record.content) if record.content is not None else None,
                            json.dumps(record.metadata), json.dumps(record.tags),
                            record.created_at.isoformat(), record.updated_at.isoformat(),
                            collection, record.record_id
                        )
                    )
                    
                text_to_embed = ""
                if isinstance(record.content, str):
                    text_to_embed = record.content
                elif record.content is not None:
                    text_to_embed = json.dumps(record.content)
                    
                if text_to_embed:
                    vector = self._encoder.encode(text_to_embed).tolist()
                    self._qdrant.upsert(
                        collection_name=collection,
                        points=[PointStruct(id=record.record_id, vector=vector, payload={"record_id": record.record_id})]
                    )
            except sqlite3.Error as e:
                raise MemoryError(f"SQLite update failed: {e}")
            except Exception as e:
                raise MemoryError(f"Qdrant update failed: {e}")
                
            return record.model_copy(deep=True)

    def delete(self, collection: str, record_id: str) -> bool:
        with self._lock:
            if not self.exists(collection, record_id):
                return False
                
            self._ensure_qdrant_collection(collection)
            try:
                with self._connect() as conn:
                    conn.execute(
                        "DELETE FROM memory_records WHERE collection = ? AND record_id = ?",
                        (collection, record_id)
                    )
                self._qdrant.delete(
                    collection_name=collection,
                    points_selector=PointIdsList(points=[record_id])
                )
                return True
            except Exception as e:
                raise MemoryError(f"Delete failed: {e}")

    def exists(self, collection: str, record_id: str) -> bool:
        with self._lock:
            try:
                with self._connect() as conn:
                    cursor = conn.execute(
                        "SELECT 1 FROM memory_records WHERE collection = ? AND record_id = ?",
                        (collection, record_id)
                    )
                    return cursor.fetchone() is not None
            except sqlite3.Error as e:
                raise MemoryError(f"SQLite error: {e}")

    def search(self, collection: str, query: MemoryQuery) -> list[MemorySearchResult]:
       with self._lock:
        self._ensure_qdrant_collection(collection)

        qdrant_scores = {}

        if query.query_text:
            try:
                vector = self._encoder.encode(query.query_text).tolist()

                try:
                    # qdrant-client >= 1.7
                    response = self._qdrant.query_points(
                        collection_name=collection,
                        query=vector,
                        limit=query.limit or 1000,
                        with_payload=True,
                    )
                    hits = response.points

                except AttributeError:
                    # Older qdrant-client versions
                    hits = self._qdrant.search(
                        collection_name=collection,
                        query_vector=vector,
                        limit=query.limit or 1000,
                        with_payload=True,
                    )

                for hit in hits:
                    qdrant_scores[str(hit.id)] = hit.score

            except Exception as e:
                raise MemoryError(f"Qdrant search failed: {e}")

        sql = "SELECT * FROM memory_records WHERE collection = ?"
        params = [collection]

        if query.record_ids:
            sql += f" AND record_id IN ({','.join(['?'] * len(query.record_ids))})"
            params.extend(query.record_ids)

        if query.record_types:
            sql += f" AND record_type IN ({','.join(['?'] * len(query.record_types))})"
            params.extend(query.record_types)

        if query.entity_ids:
            sql += f" AND entity_id IN ({','.join(['?'] * len(query.entity_ids))})"
            params.extend(query.entity_ids)

        if query.correlation_id:
            sql += " AND correlation_id = ?"
            params.append(query.correlation_id)

        if query.trace_id:
            sql += " AND trace_id = ?"
            params.append(query.trace_id)

        if query.created_after:
            sql += " AND created_at >= ?"
            params.append(query.created_after.isoformat())

        if query.created_before:
            sql += " AND created_at <= ?"
            params.append(query.created_before.isoformat())

        if query.updated_after:
            sql += " AND updated_at >= ?"
            params.append(query.updated_after.isoformat())

        if query.updated_before:
            sql += " AND updated_at <= ?"
            params.append(query.updated_before.isoformat())

        if query.query_text:
            q_ids = list(qdrant_scores.keys())

            # No semantic matches found
            if not q_ids:
                return []

            sql += f" AND record_id IN ({','.join(['?'] * len(q_ids))})"
            params.extend(q_ids)

        order_col = "created_at" if query.order_by == "created_at" else "updated_at"
        sql += f" ORDER BY {order_col} {'DESC' if query.descending else 'ASC'}"

        try:
            with self._connect() as conn:
                cursor = conn.execute(sql, params)
                rows = cursor.fetchall()
        except sqlite3.Error as e:
            raise MemoryError(f"SQLite search failed: {e}")

        results = []

        for row in rows:
            rec = self._deserialize_record(row)

            # Delegated to MemoryQuery so this backend and
            # InMemoryMemoryProvider cannot disagree about what `metadata` /
            # `metadata_any` mean. Still applied after the SQL fetch and before
            # the limit below, so `limit` continues to bound the *matching*
            # rows rather than the rows that were read.
            if not query.matches_metadata(rec.metadata):
                continue

            if query.tags:
                if not all(tag in rec.tags for tag in query.tags):
                    continue

            score = qdrant_scores.get(rec.record_id, 1.0) if query.query_text else 1.0

            results.append(
                MemorySearchResult(
                    record=rec,
                    score=score,
                )
            )

        if query.query_text:
            results.sort(key=lambda x: x.score, reverse=True)

        if query.limit:
            results = results[:query.limit]

        return results