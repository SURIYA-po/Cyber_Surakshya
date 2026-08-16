"""Builds SecurityEvents from normalized flows.

The boundary where ingestion hands off to the agent pipeline. Everything after
this point is the existing platform; everything before it is capture.

THE TIMEZONE TRAP
-----------------
cicflowmeter timestamps flows with ``datetime.fromtimestamp(t)`` — **local
time, naive**. The platform stores every timestamp in UTC.

Tagging that naive local time as UTC does not raise. It makes ``observed_at``
wrong by the host's UTC offset, so on a UTC+5:45 machine ``detected_at -
observed_at`` is roughly negative six hours. ``IncidentHistory.time_to_detect``
discards negative durations, so **every** flow would report an unmeasurable
MTTD — and the LearningAgent report would say "no incident carries the
timestamps needed to measure observation to detection", which reads like
missing data rather than a bug.

``_to_utc`` therefore interprets a naive flow timestamp as local and converts.
The whole reason Phase 0 persisted stage timestamps was to make MTTD real; a
silent offset here would have quietly undone that.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from cyber_surakshya.platform.audit.metadata import AuditMetadata
from cyber_surakshya.platform.enums.event_source import EventSource
from cyber_surakshya.platform.enums.event_type import EventType
from cyber_surakshya.platform.enums.severity import Severity
from cyber_surakshya.platform.risk.score import RiskScore
from cyber_surakshya.platform.schemas.security_event import (
    NetworkEndpoint,
    SecurityEvent,
)

logger = logging.getLogger(__name__)

# cicflowmeter's timestamp format: "2026-07-27 12:32:55".
_FLOW_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"

# NetworkEndpoint.protocol is a string; flows carry the IANA number.
_PROTOCOL_NAMES: dict[int, str] = {
    1:   "ICMP",
    6:   "TCP",
    17:  "UDP",
    47:  "GRE",
    58:  "IPv6-ICMP",
    132: "SCTP",
}

_SOURCE_SYSTEM = "network_capture"


def _to_utc(value: str | datetime | None) -> datetime | None:
    """Interpret a flow timestamp as local time and return it in UTC.

    Returns None when unparseable, so the caller can fall back explicitly
    rather than inventing an observation time.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value).strip()
        if not text:
            return None
        try:
            parsed = datetime.strptime(text, _FLOW_TIMESTAMP_FORMAT)
        except ValueError:
            try:
                parsed = datetime.fromisoformat(text)
            except ValueError:
                logger.warning(
                    "flow_timestamp_unparseable", extra={"timestamp": text[:40]}
                )
                return None

    if parsed.tzinfo is None:
        # astimezone() on a naive datetime attaches the local zone, which is
        # exactly what fromtimestamp() produced.
        parsed = parsed.astimezone()
    return parsed.astimezone(timezone.utc)


class EventBuilder:
    """Converts ingested flows into platform SecurityEvents."""

    def __init__(
        self,
        *,
        source: EventSource = EventSource.IDS,
        created_by: str = "ingestion",
    ) -> None:
        self.source     = source
        self.created_by = created_by

    def build(
        self,
        flow: Any,
        *,
        correlation_id: str,
        trace_id: str,
    ) -> SecurityEvent:
        """Build one SecurityEvent from a NormalizedFlow or StreamFlow.

        Severity and risk are deliberately left at their floor: this is a raw
        observation, and assigning it a severity here would pre-empt
        DetectionAgent and AnalysisAgent, whose job it is.
        """
        observed = _to_utc(getattr(flow, "timestamp", None))
        ingested = datetime.now(timezone.utc)

        if observed is None:
            # No usable capture time. Using ingest time keeps the event valid
            # while making MTTD read as ~0 for this flow rather than negative.
            observed = ingested
        elif observed > ingested:
            # A clock skew or a mislabelled zone would otherwise produce a
            # negative time-to-detect that silently disappears from metrics.
            logger.warning(
                "flow_observed_in_the_future",
                extra={
                    "observed_at": observed.isoformat(),
                    "ingested_at": ingested.isoformat(),
                    "skew_seconds": round((observed - ingested).total_seconds(), 1),
                },
            )
            observed = ingested

        return SecurityEvent(
            correlation_id=correlation_id,
            trace_id=trace_id,
            event_type=EventType.NETWORK_FLOW,
            source=self.source,
            severity=Severity.INFO,
            risk_score=RiskScore(value=0.0),
            title=self._title(flow),
            description=(
                f"Network flow captured from {flow.source_ip or 'unknown'} "
                f"to {flow.destination_ip or 'unknown'}."
            ),
            observed_at=observed,
            ingested_at=ingested,
            network=NetworkEndpoint(
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                source_port=flow.source_port,
                destination_port=flow.destination_port,
                protocol=self._protocol_name(getattr(flow, "protocol", None)),
            ),
            features=dict(flow.features),
            labels={
                "flow_id":    getattr(flow, "flow_id", "") or "",
                "ingestion":  _SOURCE_SYSTEM,
            },
            audit=AuditMetadata(
                created_by=self.created_by,
                updated_by=self.created_by,
                source_system=_SOURCE_SYSTEM,
            ),
        )

    def build_many(
        self,
        flows: list[Any],
        *,
        correlation_id: str,
        trace_id: str,
    ) -> list[SecurityEvent]:
        """Build a batch, skipping flows that cannot form a valid event.

        A malformed flow must not abort the batch, but the loss is counted by
        the caller rather than swallowed here.
        """
        events: list[SecurityEvent] = []
        for flow in flows:
            try:
                events.append(
                    self.build(flow, correlation_id=correlation_id, trace_id=trace_id)
                )
            except Exception as exc:
                logger.warning(
                    "security_event_build_failed",
                    extra={
                        "flow_id": (getattr(flow, "flow_id", "") or "")[:12],
                        "error":   str(exc)[:200],
                    },
                )
        return events

    # ── Private ───────────────────────────────────────────────────────────────

    @staticmethod
    def _protocol_name(protocol: Any) -> str | None:
        if protocol is None:
            return None
        try:
            number = int(protocol)
        except (TypeError, ValueError):
            return str(protocol)[:16]
        return _PROTOCOL_NAMES.get(number, str(number))

    def _title(self, flow: Any) -> str:
        protocol = self._protocol_name(getattr(flow, "protocol", None)) or "flow"
        destination = flow.destination_ip or "unknown"
        port = flow.destination_port
        target = f"{destination}:{port}" if port is not None else destination
        return f"{protocol} flow to {target}"
