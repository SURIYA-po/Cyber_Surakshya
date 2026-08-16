"""LangGraph builder for the orchestration shell."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, Iterable

from langgraph.graph import END, START, StateGraph

from cyber_surakshya.platform.state import PlatformSharedState
from graph.base_graph import GraphLifecycleHooks
from graph.config import GraphConfig

GraphNode = Callable[[PlatformSharedState], PlatformSharedState]
GraphRouter = Callable[[PlatformSharedState], str]

# Sentinel a router returns to finish the run. Mirrors
# agents.coordinator.routing.END_ROUTE without importing the agent layer —
# the graph package must not depend on any agent.
END_ROUTE = "__end__"


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
        self._coordinator: RegisteredNode | None = None
        self._router: GraphRouter | None = None
        self._routable_targets: tuple[str, ...] | None = None

    def register_coordinator(
        self,
        name: str,
        handler: GraphNode,
        router: GraphRouter,
        *,
        routable_targets: Iterable[str] | None = None,
    ) -> None:
        """Register the routing hub, switching the graph to coordinated mode.

        Without this call the builder keeps its original linear behaviour, so
        existing callers and the orchestration-shell tests are unaffected.

        Args:
            name: node name for the coordinator itself.
            handler: the coordinator node; records the routing decision.
            router: conditional-edge function returning the next node name,
                or ``END_ROUTE`` to finish the run.
            routable_targets: node names the router may emit. Validated at
                compile time so a routing/registration mismatch fails at build
                with an attributable message, rather than as a bare KeyError
                inside LangGraph's branch resolution mid-run.
        """
        normalized = name.strip()
        if not normalized:
            raise ValueError("Coordinator name must not be empty.")
        if self._coordinator is not None:
            raise ValueError("A coordinator is already registered.")
        if normalized in {node.name for node in self._nodes}:
            raise ValueError(f"Node {normalized!r} is already registered.")

        self._coordinator = RegisteredNode(name=normalized, handler=handler)
        self._router = router
        self._routable_targets = (
            tuple(routable_targets) if routable_targets is not None else None
        )
        self.logger.info(
            "graph_coordinator_registered",
            extra={"graph_name": self.config.graph_name, "node_name": normalized},
        )

    @property
    def is_coordinated(self) -> bool:
        """True when a coordinator will drive routing instead of a linear chain."""
        return self._coordinator is not None

    def register_node(self, name: str, handler: GraphNode) -> None:
        """Register a future executable graph node."""
        normalized = name.strip()
        if not normalized:
            raise ValueError("Node name must not be empty.")
        if normalized in {node.name for node in self._nodes}:
            raise ValueError(f"Node {normalized!r} is already registered.")
        if self._coordinator is not None and normalized == self._coordinator.name:
            raise ValueError(
                f"Node {normalized!r} collides with the registered coordinator."
            )
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

        Two shapes, chosen by whether a coordinator is registered:

        Linear (no coordinator) — nodes are chained in registration order.
        With no nodes at all this is a valid START -> END graph. This is the
        original behaviour and is preserved exactly.

        Coordinated — hub and spoke. START enters the coordinator, which routes
        to one worker node at a time; each worker returns to the coordinator,
        which eventually routes to END. Routing policy lives entirely in the
        supplied router; this module stays infrastructure only.
        """
        self.hooks.before_build(self.config)

        graph = StateGraph(PlatformSharedState)
        if self._coordinator is not None:
            self._build_coordinated(graph)
        else:
            self._build_linear(graph)

        compiled = graph.compile()
        self.hooks.after_build(self.config, compiled)
        return compiled

    def _build_linear(self, graph: StateGraph) -> None:
        previous = START
        for node in self._nodes:
            graph.add_node(node.name, node.handler)
            graph.add_edge(previous, node.name)
            previous = node.name
        graph.add_edge(previous, END)

    def _build_coordinated(self, graph: StateGraph) -> None:
        assert self._coordinator is not None and self._router is not None
        if not self._nodes:
            raise ValueError(
                "A coordinated graph needs at least one worker node. Register "
                "worker nodes before compiling, or omit the coordinator."
            )

        registered = {node.name for node in self._nodes}
        if self._routable_targets is not None:
            missing = sorted(set(self._routable_targets) - registered)
            if missing:
                raise ValueError(
                    f"Coordinator may route to {missing}, which are not "
                    f"registered as nodes. Registered nodes: {sorted(registered)}. "
                    "Register the missing nodes, or narrow the coordinator's "
                    "routable targets."
                )

        graph.add_node(self._coordinator.name, self._coordinator.handler)
        for node in self._nodes:
            graph.add_node(node.name, node.handler)
            # Every worker returns to the hub; only the coordinator decides
            # what happens next.
            graph.add_edge(node.name, self._coordinator.name)

        graph.add_edge(START, self._coordinator.name)
        graph.add_conditional_edges(
            self._coordinator.name,
            self._router,
            {**{node.name: node.name for node in self._nodes}, END_ROUTE: END},
        )
        self.logger.info(
            "graph_coordinated_build",
            extra={
                "graph_name":  self.config.graph_name,
                "coordinator": self._coordinator.name,
                "worker_nodes": [node.name for node in self._nodes],
            },
        )
