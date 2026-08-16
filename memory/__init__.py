"""Memory abstraction layer."""

from __future__ import annotations

from memory.base import MemoryProvider
from memory.exceptions import (
    MemoryError,
    MemoryRecordAlreadyExistsError,
    MemoryRecordNotFoundError,
    MemoryValidationError,
)
from memory.inmemory import InMemoryMemoryProvider
from memory.models import MemoryQuery, MemoryRecord, MemorySearchResult
from memory.qdrant_sqlite import QdrantSqliteMemoryProvider

# PostgreSQLMemoryProvider was removed: 430 lines of asyncpg code with zero
# call sites and zero tests, presented through this module as a supported
# backend. Reintroduce it from git history if a Postgres backend is actually
# needed — and with tests this time.
__all__ = [
    "InMemoryMemoryProvider",
    "QdrantSqliteMemoryProvider",
    "MemoryError",
    "MemoryProvider",
    "MemoryQuery",
    "MemoryRecord",
    "MemoryRecordAlreadyExistsError",
    "MemoryRecordNotFoundError",
    "MemorySearchResult",
    "MemoryValidationError",
]