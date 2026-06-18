"""Base lifecycle hooks for the orchestration shell."""

from __future__ import annotations

import logging
from typing import Any

from cyber_surakshya.platform.state import PlatformStateModel
from graph.config import GraphConfig


class GraphLifecycleHooks:
    """No-op lifecycle hooks with structured logging."""

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self.logger = logger or logging.getLogger("cyber_surakshya.graph")

    def before_build(self, config: GraphConfig) -> None:
        self.logger.info(
            "graph_build_started",
            extra={"graph_name": config.graph_name},
        )

    def after_build(self, config: GraphConfig, compiled_graph: Any) -> None:
        self.logger.info(
            "graph_build_completed",
            extra={
                "graph_name": config.graph_name,
                "compiled_graph_type": type(compiled_graph).__name__,
            },
        )

    def before_execute(self, run_id: str, state: PlatformStateModel) -> None:
        self.logger.info(
            "graph_execution_started",
            extra={
                "run_id": run_id,
                "correlation_id": state.correlation_id,
                "trace_id": state.trace_id,
                "session_id": state.session_id,
            },
        )

    def after_execute(self, run_id: str, state: PlatformStateModel) -> None:
        self.logger.info(
            "graph_execution_completed",
            extra={
                "run_id": run_id,
                "correlation_id": state.correlation_id,
                "trace_id": state.trace_id,
                "session_id": state.session_id,
            },
        )

    def on_error(
        self,
        run_id: str | None,
        error: Exception,
        state: PlatformStateModel | None = None,
    ) -> None:
        self.logger.exception(
            "graph_execution_failed",
            extra={
                "run_id": run_id,
                "error_type": type(error).__name__,
                "correlation_id": state.correlation_id if state else None,
                "trace_id": state.trace_id if state else None,
                "session_id": state.session_id if state else None,
            },
        )
