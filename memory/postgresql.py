"""PostgreSQL implementation of the MemoryProvider protocol."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, List, Optional

import asyncpg

from memory.exceptions import (
    MemoryRecordAlreadyExistsError,
    MemoryRecordNotFoundError,
    MemoryValidationError,
)
from memory.models import MemoryQuery, MemoryRecord, MemorySearchResult
from cyber_surakshya.platform.identifiers.correlation import is_valid_uuid


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _validate_non_empty_text(value: str, field_name: str) -> str:
    stripped = value.strip()
    if not stripped:
        raise ValueError(f"{field_name} must not be empty.")
    return stripped


def _validate_uuid(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        uuid_obj = uuid.UUID(value)
        return str(uuid_obj).lower()
    except ValueError:
        raise ValueError(f"Invalid UUID: {value!r}")


class PostgreSQLMemoryProvider:
    """PostgreSQL implementation of the MemoryProvider protocol."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 5432,
        database: str = "cyber_surakshya",
        user: str = "postgres",
        password: str = "password",
    ) -> None:
        self.host = host
        self.port = port
        self.database = database
        self.user = user
        self.password = password
        self.pool: Optional[asyncpg.Pool] = None
        self._connection_string = (
            f"postgresql://{user}:{password}@{host}:{port}/{database}"
        )

    async def _ensure_connection(self) -> None:
        """Ensure the connection pool is initialized."""
        if self.pool is None:
            try:
                self.pool = await asyncpg.create_pool(
                    self._connection_string,
                    min_size=1,
                    max_size=10,
                    command_timeout=60,
                )
                await self._create_tables()
            except Exception as e:
                raise ConnectionError(f"Failed to connect to PostgreSQL: {e}")

    async def _create_tables(self) -> None:
        """Create necessary tables if they don't exist."""
        if self.pool is None:
            return

        async with self.pool.acquire() as conn:
            # Main memory records table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS memory_records (
                    id UUID PRIMARY KEY,
                    backend TEXT NOT NULL,
                    collection TEXT NOT NULL,
                    record_type TEXT NOT NULL,
                    entity_id TEXT,
                    correlation_id UUID,
                    trace_id UUID,
                    content JSONB,
                    metadata JSONB DEFAULT '{}',
                    tags TEXT[] DEFAULT '{}',
                    created_at TIMESTAMPTZ NOT NULL,
                    created_at
                )
                """,
            )
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_memory_collection
                ON memory_records(collection)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_memory_record_type
                ON memory_records(record_type)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_memory_entity_id
                ON memory_records(entity_id)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_memory_correlation_id
                ON memory_records(correlation_id)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_memory_trace_id
                ON memory_records(trace_id)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_memory_created_at
                ON memory_records(created_at)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_memory_updated_at
                ON memory_records(updated_at)
            """)

    async def close(self) -> None:
        """Close the connection pool."""
        if self.pool is not None:
            await self.pool.close()
            self.pool = None

    def _record_to_dict(self, record: MemoryRecord) -> dict[str, Any]:
        """Convert a MemoryRecord to a dictionary for storage."""
        return {
            "id": record.record_id,
            "backend": record.backend,
            "collection": record.collection,
            "record_type": record.record_type,
            "entity_id": record.entity_id,
            "correlation_id": record.correlation_id,
            "trace_id": record.trace_id,
            "content": json.dumps(record.content) if record.content is not None else None,
            "metadata": json.dumps(record.metadata),
            "tags": record.tags,
            "created_at": record.created_at,
            "updated_at": record.updated_at,
        }

    def _dict_to_record(self, data: dict[str, Any]) -> MemoryRecord:
        """Convert a database row to a MemoryRecord."""
        return MemoryRecord(
            record_id=str(data["id"]),
            backend=data["backend"],
            collection=data["collection"],
            record_type=data["record_type"],
            entity_id=data["entity_id"],
            correlation_id=str(data["correlation_id"]) if data["correlation_id"] else None,
            trace_id=str(data["trace_id"]) if data["trace_id"] else None,
            content=json.loads(data["content"]) if data["content"] else None,
            metadata=json.loads(data["metadata"]) if data["metadata"] else {},
            tags=data["tags"] or [],
            created_at=data["created_at"],
            updated_at=data["updated_at"],
        )

    async def store(self, collection: str, record: MemoryRecord) -> MemoryRecord:
        """Store a record in a collection."""
        collection = self._validate_collection(collection)
        await self._ensure_connection()

        # Ensure the record has an ID
        if not record.record_id:
            record.record_id = str(uuid.uuid4())

        # Check if record already exists
        async with self.pool.acquire() as conn:
            existing = await conn.fetchrow(
                "SELECT id FROM memory_records WHERE id = $1 AND collection = $2",
                record.record_id,
                collection,
            )
            if existing:
                raise MemoryRecordAlreadyExistsError(
                    f"Record {record.record_id!r} already exists in {collection!r}."
                )

            # Store the record
            await conn.execute(
                """
                INSERT INTO memory_records (
                    id, backend, collection, record_type, entity_id,
                    correlation_id, trace_id, content, metadata, tags,
                    created_at, updated_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                """,
                record.record_id,
                record.backend,
                record.collection,
                record.record_type,
                record.entity_id,
                record.correlation_id,
                record.trace_id,
                json.dumps(record.content) if record.content is not None else None,
                json.dumps(record.metadata),
                record.tags,
                record.created_at,
                record.updated_at,
            )

        return record.model_copy(deep=True)

    async def get(self, collection: str, record_id: str) -> MemoryRecord | None:
        """Return a record by ID, or None when it does not exist."""
        collection = self._validate_collection(collection)
        record_id = self._validate_record_id(record_id)
        await self._ensure_connection()

        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT id, backend, collection, record_type, entity_id,
                       correlation_id, trace_id, content, metadata, tags,
                       created_at, updated_at
                FROM memory_records
                WHERE id = $1 AND collection = $2
                """,
                record_id,
                collection,
            )
            if row is None:
                return None
            return self._dict_to_record(dict(row))

    async def search(
        self,
        collection: str,
        query: MemoryQuery,
    ) -> List[MemorySearchResult]:
        """Search records in one collection."""
        collection = self._validate_collection(collection)
        await self._ensure_connection()

        async with self.pool.acquire() as conn:
            # Build the WHERE clause
            conditions = ["collection = $1"]
            params: List[Any] = [collection]
            param_idx = 2

            if query.record_ids is not None:
                placeholders = ", ".join([f"${i}" for i in range(param_idx, param_idx + len(query.record_ids))])
                conditions.append(f"id IN ({placeholders})")
                params.extend(query.record_ids)
                param_idx += len(query.record_ids)

            if query.record_types is not None:
                placeholders = ", ".join([f"${i}" for i in range(param_idx, param_idx + len(query.record_types))])
                conditions.append(f"record_type IN ({placeholders})")
                params.extend(query.record_types)
                param_idx += len(query.record_types)

            if query.entity_ids is not None:
                placeholders = ", ".join([f"${i}" for i in range(param_idx, param_idx + len(query.entity_ids))])
                conditions.append(f"entity_id IN ({placeholders})")
                params.extend(query.entity_ids)
                param_idx += len(query.entity_ids)

            if query.correlation_id is not None:
                conditions.append(f"correlation_id = ${param_idx}")
                params.append(query.correlation_id)
                param_idx += 1

            if query.trace_id is not None:
                conditions.append(f"trace_id = ${param_idx}")
                params.append(query.trace_id)
                param_idx += 1

            if query.metadata:
                for key, value in query.metadata.items():
                    conditions.append(f"metadata ->> ${param_idx} = ${param_idx + 1}")
                    params.extend([key, str(value)])
                    param_idx += 2

            if query.tags:
                # Check that all tags are present in the tags array
                for tag in query.tags:
                    conditions.append(f"${param_idx} = ANY(tags)")
                    params.append(tag)
                    param_idx += 1

            if query.created_after is not None:
                conditions.append(f"created_at >= ${param_idx}")
                params.append(query.created_after)
                param_idx += 1

            if query.created_before is not None:
                conditions.append(f"created_at <= ${param_idx}")
                params.append(query.created_before)
                param_idx += 1

            if query.updated_after is not None:
                conditions.append(f"updated_at >= ${param_idx}")
                params.append(query.updated_after)
                param_idx += 1

            if query.updated_before is not None:
                conditions.append(f"updated_at <= ${param_idx}")
                params.append(query.updated_before)
                param_idx += 1

            # Build the final query
            where_clause = " AND ".join(conditions)
            query_sql = f"""
                SELECT id, backend, collection, record_type, entity_id,
                       correlation_id, trace_id, content, metadata, tags,
                       created_at, updated_at
                FROM memory_records
                WHERE {where_clause}
                ORDER BY {query.order_by} {'DESC' if query.descending else 'ASC'}
            """

            if query.limit is not None:
                query_sql += f" LIMIT ${param_idx}"
                params.append(query.limit)

            # Execute the query
            rows = await conn.fetch(query_sql, *params)

            # Convert rows to MemorySearchResult objects
            results = []
            for row in rows:
                record = self._dict_to_record(dict(row))
                results.append(MemorySearchResult(record=record.model_copy(deep=True), score=None))

            return results

    async def update(self, collection: str, record: MemoryRecord) -> MemoryRecord:
        """Replace an existing record in a collection."""
        collection = self._validate_collection(collection)
        await self._ensure_connection()

        async with self.pool.acquire() as conn:
            # Check if record exists
            existing = await conn.fetchrow(
                "SELECT id FROM memory_records WHERE id = $1 AND collection = $2",
                record.record_id,
                collection,
            )
            if existing is None:
                raise MemoryRecordNotFoundError(
                    f"Record {record.record_id!r} does not exist in {collection!r}."
                )

            # Update the record
            await conn.execute(
                """
                UPDATE memory_records SET
                    backend = $2,
                    collection = $3,
                    record_type = $4,
                    entity_id = $5,
                    correlation_id = $6,
                    trace_id = $7,
                    content = $8,
                    metadata = $9,
                    tags = $10,
                    updated_at = $11
                WHERE id = $1 AND collection = $12
                """,
                record.record_id,
                record.backend,
                record.collection,
                record.record_type,
                record.entity_id,
                record.correlation_id,
                record.trace_id,
                json.dumps(record.content) if record.content is not None else None,
                json.dumps(record.metadata),
                record.tags,
                record.updated_at,
                collection,
            )

        return record.model_copy(deep=True)

    async def delete(self, collection: str, record_id: str) -> bool:
        """Delete a record by ID. Return True when deleted."""
        collection = self._validate_collection(collection)
        record_id = self._validate_record_id(record_id)
        await self._ensure_connection()

        async with self.pool.acquire() as conn:
            result = await conn.execute(
                "DELETE FROM memory_records WHERE id = $1 AND collection = $2",
                record_id,
                collection,
            )
            # DELETE returns "DELETE 1" if one row was deleted, "DELETE 0" otherwise
            deleted = result.split()[-1] == "1"
            return deleted

    async def exists(self, collection: str, record_id: str) -> bool:
        """Return True when the record exists in the collection."""
        collection = self._validate_collection(collection)
        record_id = self._validate_record_id(record_id)
        await self._ensure_connection()

        async with self.pool.acquire() as conn:
            result = await conn.fetchrow(
                "SELECT 1 FROM memory_records WHERE id = $1 AND collection = $2 LIMIT 1",
                record_id,
                collection,
            )
            return result is not None

    def _validate_collection(self, collection: str) -> str:
        if not isinstance(collection, str) or not collection.strip():
            raise MemoryValidationError("collection must be a non-empty string.")
        return collection.strip()

    def _validate_record_id(self, record_id: str) -> str:
        if not isinstance(record_id, str) or not record_id.strip():
            raise MemoryValidationError("record_id must be a non-empty string.")
        return record_id.strip()

    @property
    def backend(self) -> str:
        return "postgresql"