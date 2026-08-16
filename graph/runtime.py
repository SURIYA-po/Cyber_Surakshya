"""Execution abstraction for the LangGraph orchestration shell."""

from __future__ import annotations

import logging
from typing import Any

from cyber_surakshya.platform.state import PlatformSharedState, PlatformStateModel
from graph.base_graph import GraphLifecycleHooks
from graph.builder import GraphBuilder
from graph.checkpointing import InMemoryStatePersistence, StatePersistence
from graph.config import GraphConfig


class GraphRuntime:
    """Validate, execute, validate again, and persist graph state."""

    def __init__(
        self,
        *,
        builder: GraphBuilder | None = None,
        persistence: StatePersistence | None = None,
        config: GraphConfig | None = None,
        hooks: GraphLifecycleHooks | None = None,
        logger: logging.Logger | None = None,
        compiled_graph: Any | None = None,
    ) -> None:
        self.config = config or GraphConfig()
        self.logger = logger or logging.getLogger(self.config.logger_name)
        self.hooks = hooks or GraphLifecycleHooks(self.logger)
        self.builder = builder or GraphBuilder(
            config=self.config,
            hooks=self.hooks,
            logger=self.logger,
        )
        self.persistence = persistence or InMemoryStatePersistence()
        self._compiled_graph = compiled_graph

    def compile(self) -> Any:
        """Compile and memoize the graph executable."""
        if self._compiled_graph is None:
            self._compiled_graph = self.builder.compile()
        return self._compiled_graph

    def execute(
        self,
        state: PlatformStateModel | PlatformSharedState,
        *,
        run_id: str | None = None,
    ) -> PlatformStateModel:
        """Execute the graph for a validated platform state."""
        validated_input = self._validate_state(state)
        effective_run_id = run_id or validated_input.session_id

        try:
            self.hooks.before_execute(effective_run_id, validated_input)
            compiled = self.compile()
            output = compiled.invoke(
                validated_input.to_graph_state(),
                config={
                    "recursion_limit": self.config.effective_recursion_limit(
                        coordinated=self.builder.is_coordinated
                    )
                },
            )
            validated_output = PlatformStateModel.from_graph_state(output)
            self.persistence.save(effective_run_id, validated_output)
            self.hooks.after_execute(effective_run_id, validated_output)
            return validated_output
        except Exception as exc:
            self.hooks.on_error(effective_run_id, exc, validated_input)
            raise

    def load_state(self, run_id: str) -> PlatformStateModel | None:
        """Load a previously persisted validated state."""
        return self.persistence.load(run_id)

    def _validate_state(
        self,
        state: PlatformStateModel | PlatformSharedState,
    ) -> PlatformStateModel:
        if isinstance(state, PlatformStateModel):
            return PlatformStateModel.model_validate(state.model_dump(mode="json"))
        return PlatformStateModel.from_graph_state(state)
