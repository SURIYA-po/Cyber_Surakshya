"""Thread-safe in-memory memory provider."""

from __future__ import annotations

import logging
from copy import deepcopy
from datetime import datetime, timezone
from threading import RLock
from typing import Any

from memory.exceptions import (
    MemoryRecordAlreadyExistsError,
    MemoryRecordNotFoundError,
    MemoryValidationError,
)
from memory.models import MemoryQuery, MemoryRecord, MemorySearchResult

logger = logging.getLogger(__name__)


class InMemoryMemoryProvider:
    """Generic in-memory implementation of the MemoryProvider contract."""

    backend = "memory"

    def __init__(self) -> None:
        self._lock = RLock()
        self._collections: dict[str, dict[str, dict[str, Any]]] = {}

    def store(self, collection: str, record: MemoryRecord) -> MemoryRecord:
        collection = self._validate_collection(collection)
        with self._lock:
            bucket = self._collections.setdefault(collection, {})
            if record.record_id in bucket:
                raise MemoryRecordAlreadyExistsError(
                    f"Record {record.record_id!r} already exists in {collection!r}."
                )
            stored = self._stamp_record(collection, record)
            bucket[stored.record_id] = stored.model_dump(mode="json")
            logger.info(
                "memory_record_stored",
                extra={
                    "backend": self.backend,
                    "collection": collection,
                    "record_id": stored.record_id,
                    "record_type": stored.record_type,
                },
            )
            return stored.model_copy(deep=True)

    def get(self, collection: str, record_id: str) -> MemoryRecord | None:
        collection = self._validate_collection(collection)
        record_id = self._validate_record_id(record_id)
        with self._lock:
            payload = self._collections.get(collection, {}).get(record_id)
            logger.info(
                "memory_record_get",
                extra={
                    "backend": self.backend,
                    "collection": collection,
                    "record_id": record_id,
                    "found": payload is not None,
                },
            )
            if payload is None:
                return None
            return MemoryRecord.model_validate(deepcopy(payload))

    def search(
        self,
        collection: str,
        query: MemoryQuery,
    ) -> list[MemorySearchResult]:
        collection = self._validate_collection(collection)
        with self._lock:
            records = [
                MemoryRecord.model_validate(deepcopy(payload))
                for payload in self._collections.get(collection, {}).values()
            ]

        matches = [record for record in records if self._matches(record, query)]
        matches.sort(
            key=lambda record: getattr(record, query.order_by),
            reverse=query.descending,
        )
        if query.limit is not None:
            matches = matches[: query.limit]

        logger.info(
            "memory_search_completed",
            extra={
                "backend": self.backend,
                "collection": collection,
                "match_count": len(matches),
                "order_by": query.order_by,
                "descending": query.descending,
            },
        )
        return [
            MemorySearchResult(record=record.model_copy(deep=True), score=None)
            for record in matches
        ]

    def update(self, collection: str, record: MemoryRecord) -> MemoryRecord:
        collection = self._validate_collection(collection)
        with self._lock:
            bucket = self._collections.setdefault(collection, {})
            if record.record_id not in bucket:
                raise MemoryRecordNotFoundError(
                    f"Record {record.record_id!r} does not exist in {collection!r}."
                )
            existing = MemoryRecord.model_validate(bucket[record.record_id])
            updated = self._stamp_record(
                collection,
                record,
                created_at=existing.created_at,
                updated_at=self._utc_now(),
            )
            bucket[updated.record_id] = updated.model_dump(mode="json")
            logger.info(
                "memory_record_updated",
                extra={
                    "backend": self.backend,
                    "collection": collection,
                    "record_id": updated.record_id,
                    "record_type": updated.record_type,
                },
            )
            return updated.model_copy(deep=True)

    def delete(self, collection: str, record_id: str) -> bool:
        collection = self._validate_collection(collection)
        record_id = self._validate_record_id(record_id)
        with self._lock:
            bucket = self._collections.get(collection, {})
            deleted = bucket.pop(record_id, None) is not None
            logger.info(
                "memory_record_deleted",
                extra={
                    "backend": self.backend,
                    "collection": collection,
                    "record_id": record_id,
                    "deleted": deleted,
                },
            )
            return deleted

    def exists(self, collection: str, record_id: str) -> bool:
        collection = self._validate_collection(collection)
        record_id = self._validate_record_id(record_id)
        with self._lock:
            exists = record_id in self._collections.get(collection, {})
            logger.info(
                "memory_record_exists",
                extra={
                    "backend": self.backend,
                    "collection": collection,
                    "record_id": record_id,
                    "exists": exists,
                },
            )
            return exists

    def _stamp_record(
        self,
        collection: str,
        record: MemoryRecord,
        *,
        created_at: datetime | None = None,
        updated_at: datetime | None = None,
    ) -> MemoryRecord:
        now = self._utc_now()
        return record.model_copy(
            update={
                "backend": self.backend,
                "collection": collection,
                "created_at": created_at or record.created_at or now,
                "updated_at": updated_at or now,
            }
        )

    def _matches(self, record: MemoryRecord, query: MemoryQuery) -> bool:
        if query.record_ids is not None and record.record_id not in query.record_ids:
            return False
        if query.record_types is not None and record.record_type not in query.record_types:
            return False
        if query.entity_ids is not None and record.entity_id not in query.entity_ids:
            return False
        if query.correlation_id is not None and record.correlation_id != query.correlation_id:
            return False
        if query.trace_id is not None and record.trace_id != query.trace_id:
            return False
        if query.created_after is not None and record.created_at < query.created_after:
            return False
        if query.created_before is not None and record.created_at > query.created_before:
            return False
        if query.updated_after is not None and record.updated_at < query.updated_after:
            return False
        if query.updated_before is not None and record.updated_at > query.updated_before:
            return False
        # Both metadata filters are evaluated by MemoryQuery itself so this
        # backend and QdrantSqliteMemoryProvider cannot disagree about what
        # `metadata` / `metadata_any` mean.
        if not query.matches_metadata(record.metadata):
            return False
        if query.tags and not set(query.tags).issubset(set(record.tags)):
            return False
        return True

    def _validate_collection(self, collection: str) -> str:
        if not isinstance(collection, str) or not collection.strip():
            raise MemoryValidationError("collection must be a non-empty string.")
        return collection.strip()

    def _validate_record_id(self, record_id: str) -> str:
        if not isinstance(record_id, str) or not record_id.strip():
            raise MemoryValidationError("record_id must be a non-empty string.")
        return record_id.strip()

    def _utc_now(self) -> datetime:
        return datetime.now(timezone.utc)
