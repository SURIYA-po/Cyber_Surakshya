"""Module 1 — Outcome Collector.

Joins the four pipeline stages plus approvals and analyst feedback into a
single incident history.

Incident identity is **one detection and everything downstream of it**:

    detection ─► analysis ─► decision ─► response(s) ─► approval ─► feedback

``correlation_id`` is carried as an attribute but is deliberately NOT the key.
Since CoordinatorAgent landed, one run shares one correlation_id across many
events, so keying on it would merge unrelated incidents into one and destroy
every per-incident metric.

Partial chains are normal and are preserved: an incident awaiting approval has
no terminal response yet, and discarding it would bias metrics toward the
cases that completed quickly.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from cyber_surakshya.platform.schemas.learning_report import AnalystFeedback
from memory.base import MemoryProvider
from memory.models import MemoryQuery, MemoryRecord

logger = logging.getLogger(__name__)

# Collection names as written by the pipeline agents. "analysis" is singular
# because that is what AnalysisAgent actually writes.
DETECTIONS_COLLECTION = "detections"
ANALYSIS_COLLECTION   = "analysis"
DECISIONS_COLLECTION  = "decisions"
RESPONSES_COLLECTION  = "responses"
APPROVALS_COLLECTION  = "approvals"
FEEDBACK_COLLECTION   = "feedback"

_DEFAULT_LIMIT = 1000


def _parse_dt(value: Any) -> datetime | None:
    """Parse an ISO timestamp, returning None rather than guessing."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


@dataclass
class IncidentHistory:
    """One detection and every downstream record produced from it."""

    detection_id:   str
    event_id:       str | None      = None
    correlation_id: str | None      = None
    entity_id:      str | None      = None

    detection: dict[str, Any]       = field(default_factory=dict)
    analysis:  dict[str, Any] | None = None
    decision:  dict[str, Any] | None = None
    responses: list[dict[str, Any]] = field(default_factory=list)
    approval:  dict[str, Any] | None = None
    feedback:  AnalystFeedback | None = None

    detected_at: datetime | None = None

    # ── Derived views ─────────────────────────────────────────────────────────

    @property
    def predicted_label(self) -> str:
        return str(self.detection.get("predicted_label", "UNKNOWN"))

    @property
    def is_threat(self) -> bool:
        """True when the platform judged this a threat rather than benign."""
        status = str(self.detection.get("status", "")).upper()
        return status not in {"BENIGN", ""} and self.predicted_label.upper() != "BENIGN"

    @property
    def confidence(self) -> float | None:
        value = self.detection.get("confidence")
        return float(value) if isinstance(value, (int, float)) else None

    @property
    def action_type(self) -> str | None:
        if self.decision:
            return self.decision.get("action_type")
        return None

    @property
    def policy_name(self) -> str | None:
        if self.decision:
            return self.decision.get("policy_name")
        return None

    @property
    def terminal_response(self) -> dict[str, Any] | None:
        """The last response that is not merely awaiting approval."""
        for response in reversed(self.responses):
            if response.get("status") != "AWAITING_APPROVAL":
                return response
        return None

    @property
    def is_complete(self) -> bool:
        """True when the incident traversed the whole pipeline."""
        return bool(self.analysis and self.decision and self.terminal_response)

    @property
    def is_labeled(self) -> bool:
        """True when an analyst supplied a usable ground-truth verdict."""
        return self.feedback is not None and self.feedback.is_conclusive

    # ── Timings ───────────────────────────────────────────────────────────────

    def time_to_detect(self) -> float | None:
        """Seconds from observation to detection, or None when unmeasurable.

        Returns None for records written before stage timestamps were
        persisted. Defaulting those to zero would silently report a perfect
        MTTD built from missing data.
        """
        observed = _parse_dt(self.detection.get("observed_at"))
        detected = _parse_dt(self.detection.get("detected_at"))
        if observed is None or detected is None:
            return None
        delta = (detected - observed).total_seconds()
        return delta if delta >= 0 else None

    def time_to_respond(self) -> float | None:
        """Seconds from observation to containment, or None when unmeasurable."""
        observed = _parse_dt(self.detection.get("observed_at"))
        response = self.terminal_response
        if observed is None or response is None:
            return None
        executed = _parse_dt(response.get("executed_at"))
        if executed is None:
            return None
        delta = (executed - observed).total_seconds()
        return delta if delta >= 0 else None


class OutcomeCollector:
    """Builds incident histories from the memory layer."""

    def __init__(self, memory_provider: MemoryProvider) -> None:
        self.memory_provider = memory_provider

    def collect(
        self,
        *,
        limit: int = _DEFAULT_LIMIT,
        since: datetime | None = None,
    ) -> list[IncidentHistory]:
        """Join every stage into per-detection incident histories."""
        detections = self._load(DETECTIONS_COLLECTION, limit=limit, since=since)
        if not detections:
            return []

        analyses  = self._load(ANALYSIS_COLLECTION, limit=limit, since=since)
        decisions = self._load(DECISIONS_COLLECTION, limit=limit, since=since)
        responses = self._load(RESPONSES_COLLECTION, limit=limit, since=since)
        approvals = self._load(APPROVALS_COLLECTION, limit=limit, since=since)
        feedback  = self._load(FEEDBACK_COLLECTION, limit=limit, since=since)

        analysis_by_detection = {
            record.content["detection_id"]: record.content
            for record in analyses
            if isinstance(record.content, dict) and record.content.get("detection_id")
        }
        # Decisions link to their detection through content (new records) or
        # metadata (records written before the content was enriched).
        decision_by_detection: dict[str, dict[str, Any]] = {}
        for record in decisions:
            if not isinstance(record.content, dict):
                continue
            detection_id = (
                record.content.get("detection_id")
                or record.metadata.get("detection_id")
            )
            if detection_id:
                decision_by_detection[detection_id] = record.content

        responses_by_decision: dict[str, list[dict[str, Any]]] = {}
        for record in responses:
            if not isinstance(record.content, dict):
                continue
            decision_id = record.content.get("decision_id")
            if decision_id:
                responses_by_decision.setdefault(decision_id, []).append(record.content)

        approval_by_decision = {
            record.content["decision_id"]: record.content
            for record in approvals
            if isinstance(record.content, dict) and record.content.get("decision_id")
        }
        feedback_by_detection = self._parse_feedback(feedback)

        incidents: list[IncidentHistory] = []
        for record in detections:
            if not isinstance(record.content, dict):
                continue
            detection_id = record.content.get("detection_id")
            if not detection_id:
                continue

            decision = decision_by_detection.get(detection_id)
            decision_id = decision.get("decision_id") if decision else None

            incidents.append(
                IncidentHistory(
                    detection_id=detection_id,
                    event_id=record.content.get("event_id"),
                    correlation_id=record.correlation_id,
                    entity_id=record.entity_id,
                    detection=record.content,
                    analysis=analysis_by_detection.get(detection_id),
                    decision=decision,
                    responses=responses_by_decision.get(decision_id, []) if decision_id else [],
                    approval=approval_by_decision.get(decision_id) if decision_id else None,
                    feedback=feedback_by_detection.get(detection_id),
                    detected_at=_parse_dt(record.content.get("detected_at")) or record.created_at,
                )
            )

        logger.info(
            "learning_outcomes_collected",
            extra={
                "incidents": len(incidents),
                "complete":  sum(1 for i in incidents if i.is_complete),
                "labeled":   sum(1 for i in incidents if i.is_labeled),
            },
        )
        return incidents

    # ── Private ───────────────────────────────────────────────────────────────

    def _load(
        self,
        collection: str,
        *,
        limit: int,
        since: datetime | None,
    ) -> list[MemoryRecord]:
        """Read a collection, treating an unreadable one as empty.

        A missing collection is normal on a fresh install; failing the whole
        report because one stage has no history yet would make the agent
        unusable exactly when it is first switched on.
        """
        try:
            hits = self.memory_provider.search(
                collection,
                MemoryQuery(
                    limit=limit,
                    order_by="created_at",
                    descending=True,
                    created_after=since,
                ),
            )
        except Exception as exc:
            logger.warning(
                "learning_collection_unavailable",
                extra={"collection": collection, "error": str(exc)},
            )
            return []
        return [hit.record for hit in hits]

    @staticmethod
    def _parse_feedback(records: list[MemoryRecord]) -> dict[str, AnalystFeedback]:
        """Rebuild feedback models, keeping the most recent per detection."""
        parsed: dict[str, AnalystFeedback] = {}
        for record in records:
            if not isinstance(record.content, dict):
                continue
            try:
                feedback = AnalystFeedback.model_validate(record.content)
            except Exception as exc:
                logger.warning(
                    "learning_feedback_unparseable",
                    extra={"record_id": record.record_id, "error": str(exc)},
                )
                continue
            existing = parsed.get(feedback.detection_id)
            if existing is None or feedback.recorded_at > existing.recorded_at:
                parsed[feedback.detection_id] = feedback
        return parsed
