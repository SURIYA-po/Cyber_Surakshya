"""Module 5 — Feedback Recorder.

Analyst verdicts are the only ground truth the platform has. It cannot detect
its own false positives by introspection: a confident wrong answer is
indistinguishable from a confident right one. Everything the MetricsEngine
knows about accuracy comes from here.

That is why this module is an **input** to metrics rather than a trailing
sink, and why a failed write is raised rather than swallowed. Most memory
failures in this platform are logged and ignored — losing an audit copy is
survivable. Silently losing a verdict is not: it corrupts every accuracy
number computed afterwards, invisibly and permanently.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from agents.learning.exceptions import FeedbackStoreError
from agents.learning.outcome_collector import FEEDBACK_COLLECTION
from cyber_surakshya.platform.schemas.learning_report import (
    AnalystFeedback,
    AnalystVerdict,
)
from memory.base import MemoryProvider
from memory.models import MemoryQuery, MemoryRecord

logger = logging.getLogger(__name__)

_RECORD_TYPE = "analyst_feedback"


class FeedbackRecorder:
    """Writes and reads analyst verdicts on platform decisions."""

    def __init__(self, memory_provider: MemoryProvider) -> None:
        self.memory_provider = memory_provider

    def record(
        self,
        *,
        detection_id: str,
        verdict: AnalystVerdict | str,
        analyst: str,
        decision_id: str | None = None,
        notes: str | None = None,
        predicted_label: str | None = None,
        actual_label: str | None = None,
    ) -> AnalystFeedback:
        """Store one analyst ruling.

        Feedback is append-only. A corrected verdict is a new record, and the
        collector takes the most recent per detection — so an analyst changing
        their mind is preserved as history rather than overwriting it.

        Raises:
            FeedbackStoreError: the verdict could not be persisted.
        """
        resolved = (
            verdict if isinstance(verdict, AnalystVerdict) else AnalystVerdict(str(verdict).upper())
        )
        feedback = AnalystFeedback(
            detection_id=detection_id,
            decision_id=decision_id,
            verdict=resolved,
            analyst=analyst,
            notes=notes,
            predicted_label=predicted_label,
            actual_label=actual_label,
            recorded_at=datetime.now(timezone.utc),
        )

        record = MemoryRecord(
            backend="qdrant_sqlite",
            collection=FEEDBACK_COLLECTION,
            record_type=_RECORD_TYPE,
            entity_id=detection_id,
            content=feedback.model_dump(mode="json"),
            metadata={
                "agent":        "learning_agent",
                "verdict":      resolved.value,
                "analyst":      analyst,
                "detection_id": detection_id,
                "conclusive":   feedback.is_conclusive,
            },
            tags=["learning_agent", "feedback", resolved.value],
        )

        try:
            self.memory_provider.store(FEEDBACK_COLLECTION, record)
        except Exception as exc:
            logger.error(
                "learning_feedback_store_failed",
                extra={
                    "detection_id": detection_id,
                    "verdict":      resolved.value,
                    "error":        str(exc),
                },
            )
            raise FeedbackStoreError(
                f"Could not persist analyst feedback for detection "
                f"{detection_id!r}: {exc}"
            ) from exc

        logger.info(
            "learning_feedback_recorded",
            extra={
                "feedback_id":  feedback.feedback_id,
                "detection_id": detection_id,
                "verdict":      resolved.value,
                "analyst":      analyst,
                "conclusive":   feedback.is_conclusive,
            },
        )
        return feedback

    def get(self, detection_id: str) -> AnalystFeedback | None:
        """Return the most recent verdict for a detection, if any."""
        try:
            hits = self.memory_provider.search(
                FEEDBACK_COLLECTION,
                MemoryQuery(
                    record_types=[_RECORD_TYPE],
                    entity_ids=[detection_id],
                    order_by="created_at",
                    descending=True,
                    limit=1,
                ),
            )
        except Exception as exc:
            logger.warning(
                "learning_feedback_lookup_failed",
                extra={"detection_id": detection_id, "error": str(exc)},
            )
            return None

        for hit in hits:
            if isinstance(hit.record.content, dict):
                try:
                    return AnalystFeedback.model_validate(hit.record.content)
                except Exception:
                    continue
        return None

    def list_feedback(self, *, limit: int = 200) -> list[AnalystFeedback]:
        """Return recent verdicts, newest first."""
        try:
            hits = self.memory_provider.search(
                FEEDBACK_COLLECTION,
                MemoryQuery(
                    record_types=[_RECORD_TYPE],
                    order_by="created_at",
                    descending=True,
                    limit=limit,
                ),
            )
        except Exception as exc:
            logger.warning(
                "learning_feedback_list_failed",
                extra={"error": str(exc)},
            )
            return []

        results: list[AnalystFeedback] = []
        for hit in hits:
            if not isinstance(hit.record.content, dict):
                continue
            try:
                results.append(AnalystFeedback.model_validate(hit.record.content))
            except Exception:
                continue
        return results
