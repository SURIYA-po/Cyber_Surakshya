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
