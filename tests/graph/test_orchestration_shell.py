"""Tests for the LangGraph orchestration shell."""

from __future__ import annotations

from typing import Any

import pytest

from cyber_surakshya.platform.state import (
    PlatformSharedState,
    PlatformStateModel,
    create_initial_state,
)
from graph.base_graph import GraphLifecycleHooks
from graph.builder import GraphBuilder
from graph.checkpointing import InMemoryStatePersistence
from graph.config import GraphConfig
from graph.runtime import GraphRuntime


class RecordingHooks(GraphLifecycleHooks):
    def __init__(self) -> None:
        super().__init__()
        self.events: list[str] = []

    def before_build(self, config: GraphConfig) -> None:
        self.events.append("before_build")

    def after_build(self, config: GraphConfig, compiled_graph: Any) -> None:
        self.events.append("after_build")

    def before_execute(self, run_id: str, state: PlatformStateModel) -> None:
        self.events.append("before_execute")

    def after_execute(self, run_id: str, state: PlatformStateModel) -> None:
        self.events.append("after_execute")

    def on_error(
        self,
        run_id: str | None,
        error: Exception,
        state: PlatformStateModel | None = None,
    ) -> None:
        self.events.append("on_error")


def test_start_to_end_graph_executes_platform_state_model():
    initial = create_initial_state(metadata={"source": "test"})
    persistence = InMemoryStatePersistence()
    runtime = GraphRuntime(persistence=persistence)

    result = runtime.execute(initial, run_id="run-1")

    assert result == initial
    assert persistence.load("run-1") == initial


def test_runtime_accepts_platform_shared_state():
    initial = create_initial_state()
    runtime = GraphRuntime()

    result = runtime.execute(initial.to_graph_state(), run_id="run-2")

    assert result == initial


def test_runtime_validates_input_state_before_execution():
    persistence = InMemoryStatePersistence()
    runtime = GraphRuntime(persistence=persistence)
    invalid_state = PlatformSharedState(
        correlation_id="not-a-uuid",
        trace_id="not-a-uuid",
        session_id="not-a-uuid",
        metadata={},
    )

    with pytest.raises(ValueError):
        runtime.execute(invalid_state, run_id="invalid")

    assert persistence.load("invalid") is None


def test_in_memory_persistence_stores_serialized_state_payload():
    state = create_initial_state(metadata={"component": "graph"})
    persistence = InMemoryStatePersistence()

    persistence.save("serialized-run", state)

    raw_payload = persistence.raw_payload("serialized-run")
    assert raw_payload is not None
    assert isinstance(raw_payload, dict)
    assert raw_payload == state.model_dump(mode="json")
    assert raw_payload is not state
    assert persistence.load("serialized-run") == state


def test_lifecycle_hooks_fire_for_build_and_execution():
    hooks = RecordingHooks()
    runtime = GraphRuntime(hooks=hooks)

    runtime.execute(create_initial_state(), run_id="hooks-run")

    assert hooks.events == [
        "before_execute",
        "before_build",
        "after_build",
        "after_execute",
    ]


def test_future_node_registration_supports_noop_node():
    builder = GraphBuilder()

    def noop_node(state: PlatformSharedState) -> PlatformSharedState:
        return PlatformSharedState(metadata={"noop_node": "visited"})

    builder.register_node("noop", noop_node)
    runtime = GraphRuntime(builder=builder)

    result = runtime.execute(create_initial_state(), run_id="noop-run")

    assert result.metadata == {"noop_node": "visited"}
    assert [node.name for node in builder.registered_nodes] == ["noop"]
