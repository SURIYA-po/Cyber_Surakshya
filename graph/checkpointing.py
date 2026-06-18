"""State persistence abstractions for graph execution."""

from __future__ import annotations

from abc import ABC, abstractmethod
from copy import deepcopy
from typing import Any

from cyber_surakshya.platform.state import PlatformStateModel

SerializedState = dict[str, Any]


class StatePersistence(ABC):
    """
    Persistence boundary for platform state snapshots.

    Implementations store serialized state payloads so future backends can use
    databases, object stores, or LangGraph persistence without holding live
    Pydantic objects.
    """

    @abstractmethod
    def save(self, run_id: str, state: PlatformStateModel) -> None:
        """Persist a validated state snapshot."""

    @abstractmethod
    def load(self, run_id: str) -> PlatformStateModel | None:
        """Load and validate a persisted state snapshot."""


class InMemoryStatePersistence(StatePersistence):
    """In-memory serialized-state persistence for tests and local execution."""

    def __init__(self) -> None:
        self._store: dict[str, SerializedState] = {}

    def save(self, run_id: str, state: PlatformStateModel) -> None:
        self._store[run_id] = deepcopy(state.model_dump(mode="json"))

    def load(self, run_id: str) -> PlatformStateModel | None:
        payload = self._store.get(run_id)
        if payload is None:
            return None
        return PlatformStateModel.model_validate(deepcopy(payload))

    def raw_payload(self, run_id: str) -> SerializedState | None:
        """Return the serialized payload for assertions and diagnostics."""
        payload = self._store.get(run_id)
        if payload is None:
            return None
        return deepcopy(payload)
