"""Configuration for the LangGraph orchestration shell."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class GraphConfig(BaseModel):
    """Runtime configuration for graph construction and execution."""

    model_config = ConfigDict(extra="forbid")

    graph_name: str = Field(default="cyber-surakshya-orchestration-shell")
    recursion_limit: int = Field(default=25, ge=1)
    checkpoint_namespace: str = Field(default="default", min_length=1)
    logger_name: str = Field(default="cyber_surakshya.graph", min_length=1)

    coordinator_max_iterations: int = Field(
        default=100,
        ge=1,
        description=(
            "Maximum coordinator dispatches per run. Only meaningful when a "
            "coordinator is registered on the builder."
        ),
    )

    def effective_recursion_limit(self, *, coordinated: bool) -> int:
        """Recursion limit to hand LangGraph for this run.

        In coordinated mode each work item costs two super-steps (agent plus
        coordinator), so the default of 25 would abort a three-event run with
        an opaque LangGraph error. Deriving the limit from the coordinator's
        own budget makes the coordinator the thing that stops a run, and keeps
        its termination report the authoritative explanation.

        The configured ``recursion_limit`` still wins when it is larger, so an
        operator can always raise it explicitly.
        """
        if not coordinated:
            return self.recursion_limit
        derived = self.coordinator_max_iterations * 2 + 4   # + START/END headroom
        return max(self.recursion_limit, derived)
