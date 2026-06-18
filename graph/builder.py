"""LangGraph builder for the orchestration shell."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable

from langgraph.graph import END, START, StateGraph

from cyber_surakshya.platform.state import PlatformSharedState
from graph.base_graph import GraphLifecycleHooks
from graph.config import GraphConfig

GraphNode = Callable[[PlatformSharedState], PlatformSharedState]


@dataclass(frozen=True)
class RegisteredNode:
    """A future graph node registration without agent-specific behavior."""

    name: str
    handler: GraphNode


class GraphBuilder:
    """Build and compile the minimal Cyber Surakshya LangGraph shell."""

    def __init__(
        self,
        config: GraphConfig | None = None,
        hooks: GraphLifecycleHooks | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self.config = config or GraphConfig()
        self.logger = logger or logging.getLogger(self.config.logger_name)
        self.hooks = hooks or GraphLifecycleHooks(self.logger)
        self._nodes: list[RegisteredNode] = []

    def register_node(self, name: str, handler: GraphNode) -> None:
        """Register a future executable graph node."""
        normalized = name.strip()
        if not normalized:
            raise ValueError("Node name must not be empty.")
        if normalized in {node.name for node in self._nodes}:
            raise ValueError(f"Node {normalized!r} is already registered.")
        self._nodes.append(RegisteredNode(name=normalized, handler=handler))
        self.logger.info(
            "graph_node_registered",
            extra={"graph_name": self.config.graph_name, "node_name": normalized},
        )

    @property
    def registered_nodes(self) -> tuple[RegisteredNode, ...]:
        """Return registered nodes for diagnostics and tests."""
        return tuple(self._nodes)

    def compile(self):
        """Compile a LangGraph executable.

        With no registered nodes, this produces a valid START -> END graph.
        Registered nodes are chained linearly in registration order. This is
        infrastructure only; it does not define security routing policy.
        """
        self.hooks.before_build(self.config)

        graph = StateGraph(PlatformSharedState)
        previous = START
        for node in self._nodes:
            graph.add_node(node.name, node.handler)
            graph.add_edge(previous, node.name)
            previous = node.name
        graph.add_edge(previous, END)

        compiled = graph.compile()
        self.hooks.after_build(self.config, compiled)
        return compiled
