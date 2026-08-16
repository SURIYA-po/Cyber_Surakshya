"""Observability plumbing: turning the platform's own logs into a live feed."""

from observability.event_log import (
    AGENT_LOGGER_PREFIXES,
    PlatformEvent,
    PlatformEventLog,
    attach_to_loggers,
    event_log,
)
from observability.metrics import MetricsWriter, render_platform_metrics

__all__ = [
    "AGENT_LOGGER_PREFIXES",
    "MetricsWriter",
    "PlatformEvent",
    "PlatformEventLog",
    "attach_to_loggers",
    "event_log",
    "render_platform_metrics",
]
