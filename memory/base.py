"""Memory provider interface."""

from __future__ import annotations

from typing import Protocol

from memory.models import MemoryQuery, MemoryRecord, MemorySearchResult


class MemoryProvider(Protocol):
    """Generic memory port implemented by concrete storage adapters."""

    def store(self, collection: str, record: MemoryRecord) -> MemoryRecord:
        """Store a record in a collection."""

    def get(self, collection: str, record_id: str) -> MemoryRecord | None:
        """Return a record by ID, or None when it does not exist."""

    def search(
        self,
        collection: str,
        query: MemoryQuery,
    ) -> list[MemorySearchResult]:
        """Search records in one collection."""

    def update(self, collection: str, record: MemoryRecord) -> MemoryRecord:
        """Replace an existing record in a collection."""

    def delete(self, collection: str, record_id: str) -> bool:
        """Delete a record by ID. Return True when deleted."""

    def exists(self, collection: str, record_id: str) -> bool:
        """Return True when the record exists in the collection."""
