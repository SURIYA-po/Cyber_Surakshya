"""A bounded, thread-safe ring buffer of real platform log events.

WHY THIS EXISTS
---------------
The dashboard's `/feed` SSE endpoint used to emit randomly chosen strings from
a hardcoded list whenever an alert had been created in the last 15 seconds:

    "Applying VotingEnsemble / Random Forest model..."
    "Evaluating anomaly layer (Isolation Forest + Autoencoder)..."
    "Cross-referencing IOCs..."
    "Updating behavioral baseline..."

None described anything that happened. Two described capabilities the platform
does not have at all -- there is no IOC cross-referencing and no behavioural
baseline anywhere in the codebase. A reviewer watching that feed was shown a
system more capable than the one running.

The agents already emit richly structured log events (`detection_agent_started`,
`bridge_batch_completed`, `ingestion_retention_swept`, ...) via the standard
logging module. This turns those into the feed, so what the dashboard shows is
what actually executed.

DESIGN
------
A logging.Handler appends to a deque with a fixed maxlen, so memory is bounded
no matter how long the server runs or how loud the pipeline gets. Readers take
a monotonically increasing cursor rather than popping, so several SSE clients
can follow the same stream independently.

The handler NEVER raises: an observability failure must not break the pipeline
it is observing.
"""
from __future__ import annotations

import logging
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# Loggers whose records become feed events. Everything else (uvicorn access
# logs, httpx chatter, sentence-transformers progress) is ignored -- the feed
# is the platform's story, not the process's.
AGENT_LOGGER_PREFIXES: tuple[str, ...] = (
    "agents.",
    "adapters.",
    "ingestion.",
    "cyber_surakshya.graph",
)

# Maps a logger name onto the agent identity the dashboard groups by.
_AGENT_IDS: tuple[tuple[str, str], ...] = (
    ("agents.detection",      "agent-detect-01"),
    ("agents.analysis",       "agent-analysis-01"),
    ("agents.decision",       "agent-decision-01"),
    ("agents.response",       "agent-response-01"),
    ("agents.coordinator",    "agent-coordinator-01"),
    ("agents.learning",       "agent-learning-01"),
    ("adapters.detection",    "agent-detect-01"),
    ("adapters.response",     "agent-response-01"),
    ("ingestion",             "ingestion-01"),
    ("cyber_surakshya.graph", "graph-runtime"),
)

_DEFAULT_CAPACITY = 500


def _agent_id_for(logger_name: str) -> str:
    for prefix, agent_id in _AGENT_IDS:
        if logger_name.startswith(prefix):
            return agent_id
    return "platform"


def _status_for(levelno: int) -> str:
    if levelno >= logging.ERROR:
        return "ERROR"
    if levelno >= logging.WARNING:
        return "WARN"
    return "BUSY"


@dataclass(frozen=True)
class PlatformEvent:
    """One real log record, in the shape the dashboard consumes."""

    seq:       int
    agent_id:  str
    msg:       str
    timestamp: str
    status:    str
    logger:    str
    context:   dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "agent_id":  self.agent_id,
            "msg":       self.msg,
            "timestamp": self.timestamp,
            "status":    self.status,
            "logger":    self.logger,
            "context":   self.context,
            "seq":       self.seq,
        }


# Structured `extra=` keys worth surfacing. A whitelist rather than "everything
# not a LogRecord builtin", because agents pass objects that are not JSON
# serialisable and the feed must never fail to encode.
_CONTEXT_KEYS = (
    "event_id", "detection_id", "correlation_id", "predicted_label",
    "confidence", "status", "risk_score", "severity", "agent", "adapter",
    "events", "detections", "decisions", "responses", "pending_total",
    "flows", "published", "rejected", "deleted", "interface", "backend",
    "error_type", "feature_count", "model_name", "anomaly_ready",
)


class PlatformEventLog:
    """Bounded ring buffer of platform events with a monotonic cursor."""

    def __init__(self, capacity: int = _DEFAULT_CAPACITY) -> None:
        self._events: deque[PlatformEvent] = deque(maxlen=capacity)
        self._lock = threading.Lock()
        self._seq = 0

    def append(self, event_fields: dict[str, Any]) -> PlatformEvent:
        with self._lock:
            self._seq += 1
            event = PlatformEvent(seq=self._seq, **event_fields)
            self._events.append(event)
            return event

    def since(self, cursor: int, limit: int = 50) -> list[PlatformEvent]:
        """Return events newer than `cursor`, oldest first."""
        with self._lock:
            fresh = [e for e in self._events if e.seq > cursor]
        return fresh[:limit]

    def latest_seq(self) -> int:
        with self._lock:
            return self._seq

    def recent(self, limit: int = 50) -> list[PlatformEvent]:
        with self._lock:
            return list(self._events)[-limit:]

    def clear(self) -> None:
        with self._lock:
            self._events.clear()


class _EventLogHandler(logging.Handler):
    """Feeds selected log records into a PlatformEventLog."""

    def __init__(self, log: PlatformEventLog, level: int = logging.INFO) -> None:
        super().__init__(level=level)
        self._log = log

    def emit(self, record: logging.LogRecord) -> None:
        try:
            if not record.name.startswith(AGENT_LOGGER_PREFIXES):
                return

            context = {
                key: record.__dict__[key]
                for key in _CONTEXT_KEYS
                if key in record.__dict__ and _is_jsonable(record.__dict__[key])
            }
            self._log.append({
                "agent_id":  _agent_id_for(record.name),
                "msg":       record.getMessage(),
                "timestamp": datetime.fromtimestamp(
                    record.created, tz=timezone.utc
                ).isoformat().replace("+00:00", "Z"),
                "status":    _status_for(record.levelno),
                "logger":    record.name,
                "context":   context,
            })
        except Exception:
            # An observability failure must never break the pipeline being
            # observed. Handler errors are deliberately swallowed.
            pass


def _is_jsonable(value: Any) -> bool:
    return value is None or isinstance(value, (str, int, float, bool, list, dict))


# Process-wide singleton. The SSE endpoint and the agents share one buffer.
event_log = PlatformEventLog()

_attached = False
_attach_lock = threading.Lock()


def attach_to_loggers(log: PlatformEventLog | None = None) -> None:
    """Install the handler on the root logger. Idempotent.

    Attaching to root rather than to each agent logger means a new agent module
    is captured without being registered anywhere; the prefix filter in
    `emit` keeps the feed to platform events.
    """
    global _attached
    with _attach_lock:
        if _attached:
            return
        target = log or event_log
        handler = _EventLogHandler(target)
        root = logging.getLogger()
        root.addHandler(handler)
        # Agents log at INFO. Without this the records never reach any handler,
        # because the root logger defaults to WARNING.
        if root.level > logging.INFO or root.level == logging.NOTSET:
            root.setLevel(logging.INFO)
        _attached = True
