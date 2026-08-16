"""Bridge between ingested flows and the agent pipeline."""
from __future__ import annotations

from ingestion.bridge.event_builder import EventBuilder
from ingestion.bridge.pipeline_bridge import (
    DEFAULT_MAX_EVENTS_PER_RUN,
    PIPELINE_STAGES,
    BridgeStats,
    PipelineBridge,
)

__all__ = [
    "DEFAULT_MAX_EVENTS_PER_RUN",
    "PIPELINE_STAGES",
    "BridgeStats",
    "EventBuilder",
    "PipelineBridge",
]
