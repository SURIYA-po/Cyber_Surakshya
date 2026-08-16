"""Learning Agent — outcome feedback and improvement analysis.

Orchestrates five modules:

    OutcomeCollector ─┐
                      ├─► MetricsEngine ─► PatternDiscovery ─► RecommendationEngine
    FeedbackRecorder ─┘                                              │
                                                                     ▼
                                                              LearningReport

FeedbackRecorder is an INPUT to the metrics, not a trailing sink: false
positives, false negatives, and accuracy are undefined without analyst labels,
because the platform cannot detect its own mistakes by introspection.

Responsibilities (strict boundary):
  DOES:
    - Join historical records into per-detection incident histories
    - Compute metrics, qualified by the evidence available
    - Discover recurring patterns
    - Emit ranked, advisory recommendations
    - Record and read analyst feedback
    - Persist a LearningReport for audit and trend tracking

  DOES NOT:
    - Retrain, fine-tune, or modify any model
    - Modify policy, thresholds, or config/response_policy.yaml
    - Execute containment, or influence any live decision
    - Participate in the per-event pipeline

Not a pipeline node. Detection, analysis, decision, and response run per
event; learning runs over history. Registering it in the coordinated graph
would re-derive platform-wide metrics on every flow and make each event's
latency depend on archive size. It is invoked on demand or on a schedule.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

from agents.learning.feedback import FeedbackRecorder
from agents.learning.metrics_engine import DEFAULT_MIN_SAMPLE_SIZE, MetricsEngine
from agents.learning.outcome_collector import IncidentHistory, OutcomeCollector
from agents.learning.pattern_discovery import PatternDiscovery
from agents.learning.recommendation_engine import RecommendationEngine
from cyber_surakshya.platform.audit.metadata import AuditMetadata
from cyber_surakshya.platform.schemas.learning_report import (
    AnalystFeedback,
    AnalystVerdict,
    LearningReport,
)
from cyber_surakshya.platform.state import PlatformSharedState, PlatformStateModel
from memory.base import MemoryProvider
from memory.models import MemoryQuery, MemoryRecord

logger = logging.getLogger(__name__)

REPORTS_COLLECTION = "learning_reports"
_RECORD_TYPE = "learning_report"


class LearningAgent:
    """Analyses incident history and proposes improvements."""

    def __init__(
        self,
        memory_provider: MemoryProvider,
        *,
        outcome_collector: OutcomeCollector | None = None,
        feedback_recorder: FeedbackRecorder | None = None,
        metrics_engine: MetricsEngine | None = None,
        pattern_discovery: PatternDiscovery | None = None,
        recommendation_engine: RecommendationEngine | None = None,
        min_sample_size: int = DEFAULT_MIN_SAMPLE_SIZE,
        agent_name: str = "learning_agent",
    ) -> None:
        self.memory_provider       = memory_provider
        self.outcome_collector     = outcome_collector or OutcomeCollector(memory_provider)
        self.feedback_recorder     = feedback_recorder or FeedbackRecorder(memory_provider)
        self.metrics_engine        = metrics_engine or MetricsEngine(
            min_sample_size=min_sample_size
        )
        self.pattern_discovery     = pattern_discovery or PatternDiscovery()
        self.recommendation_engine = recommendation_engine or RecommendationEngine()
        self.min_sample_size       = min_sample_size
        self.agent_name            = agent_name

    # ── Primary entry point ───────────────────────────────────────────────────

    def analyze(
        self,
        *,
        limit: int = 1000,
        since: datetime | None = None,
        persist: bool = True,
    ) -> LearningReport:
        """Run the full learning cycle and return a report.

        An empty history produces an empty report rather than an error:
        "we have learned nothing yet" is a valid and useful answer, and the
        agent must be usable the day it is switched on.
        """
        started = time.perf_counter()

        incidents = self.outcome_collector.collect(limit=limit, since=since)
        metrics   = self.metrics_engine.compute(incidents)
        patterns  = self.pattern_discovery.discover(incidents)

        labeled  = sum(1 for i in incidents if i.is_labeled)
        coverage = (labeled / len(incidents)) if incidents else 0.0

        recommendations = self.recommendation_engine.recommend(
            metrics,
            patterns,
            feedback_coverage=coverage,
            total_incidents=len(incidents),
        )

        window_start, window_end = self._window(incidents)
        report = LearningReport(
            total_incidents=len(incidents),
            complete_incidents=sum(1 for i in incidents if i.is_complete),
            labeled_incidents=labeled,
            feedback_coverage=coverage,
            window_start=window_start,
            window_end=window_end,
            metrics=metrics,
            patterns=patterns,
            recommendations=recommendations,
            analysis_duration_ms=round((time.perf_counter() - started) * 1000.0, 3),
            min_sample_size=self.min_sample_size,
            metadata={
                "agent":              self.agent_name,
                "incident_limit":     limit,
                "since":              since.isoformat() if since else None,
            },
            audit=AuditMetadata(
                created_by=self.agent_name,
                updated_by=self.agent_name,
                source_system="learning_pipeline",
            ),
        )

        if persist:
            self._store_report(report)

        logger.info(
            "learning_analysis_completed",
            extra={
                "agent":             self.agent_name,
                "report_id":         report.report_id,
                "incidents":         report.total_incidents,
                "labeled":           report.labeled_incidents,
                "feedback_coverage": round(coverage, 3),
                "patterns":          len(patterns),
                "recommendations":   len(recommendations),
                "duration_ms":       report.analysis_duration_ms,
            },
        )
        return report

    # ── Feedback (delegated to module 5) ──────────────────────────────────────

    def record_feedback(
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
        """Record an analyst verdict — the platform's only ground truth."""
        return self.feedback_recorder.record(
            detection_id=detection_id,
            verdict=verdict,
            analyst=analyst,
            decision_id=decision_id,
            notes=notes,
            predicted_label=predicted_label,
            actual_label=actual_label,
        )

    def list_feedback(self, *, limit: int = 200) -> list[AnalystFeedback]:
        """Return recent analyst verdicts, newest first."""
        return self.feedback_recorder.list_feedback(limit=limit)

    # ── Reports ───────────────────────────────────────────────────────────────

    def latest_report(self) -> dict | None:
        """Return the most recently persisted report payload, if any."""
        reports = self.list_reports(limit=1)
        return reports[0] if reports else None

    def list_reports(self, *, limit: int = 20) -> list[dict]:
        """Return persisted report payloads, newest first."""
        try:
            hits = self.memory_provider.search(
                REPORTS_COLLECTION,
                MemoryQuery(
                    record_types=[_RECORD_TYPE],
                    order_by="created_at",
                    descending=True,
                    limit=limit,
                ),
            )
        except Exception as exc:
            logger.warning(
                "learning_report_list_failed",
                extra={"agent": self.agent_name, "error": str(exc)},
            )
            return []
        return [
            hit.record.content
            for hit in hits
            if isinstance(hit.record.content, dict)
        ]

    # ── LangGraph compatibility ───────────────────────────────────────────────

    def __call__(self, state: PlatformSharedState) -> PlatformSharedState:
        """Graph-node form, for use in a dedicated learning graph.

        Reports summary counts into metadata only. It appends nothing to any
        result list, and PlatformSharedState has no learning_reports field:
        a report describes history, not the run that produced it.
        """
        try:
            state_model = PlatformStateModel.from_graph_state(state)
            report = self.analyze()
            return PlatformSharedState(
                correlation_id=state_model.correlation_id,
                trace_id=state_model.trace_id,
                session_id=state_model.session_id,
                metadata={
                    **state_model.metadata,
                    self.agent_name: {
                        "status":            "completed",
                        "report_id":         report.report_id,
                        "total_incidents":   report.total_incidents,
                        "labeled_incidents": report.labeled_incidents,
                        "feedback_coverage": round(report.feedback_coverage, 3),
                        "patterns":          len(report.patterns),
                        "recommendations":   len(report.recommendations),
                    },
                },
            )
        except Exception as exc:
            logger.exception(
                "learning_agent_failed",
                extra={"agent": self.agent_name, "error_type": type(exc).__name__},
            )
            return PlatformSharedState(
                errors=[f"{self.agent_name}: {exc}"],
                metadata={
                    self.agent_name: {
                        "status":     "failed",
                        "error_type": type(exc).__name__,
                    }
                },
            )

    # ── Private ───────────────────────────────────────────────────────────────

    @staticmethod
    def _window(
        incidents: list[IncidentHistory],
    ) -> tuple[datetime | None, datetime | None]:
        stamps = sorted(i.detected_at for i in incidents if i.detected_at)
        if not stamps:
            return None, None
        return stamps[0], stamps[-1]

    def _store_report(self, report: LearningReport) -> None:
        """Persist the report for audit and trend tracking.

        A storage failure is logged rather than raised: the report has already
        been computed and returned, and losing the archived copy must not fail
        the caller. Analyst feedback is the opposite case — see feedback.py.
        """
        try:
            record = MemoryRecord(
                backend="qdrant_sqlite",
                collection=REPORTS_COLLECTION,
                record_type=_RECORD_TYPE,
                entity_id=report.report_id,
                content=report.model_dump(mode="json"),
                metadata={
                    "agent":             self.agent_name,
                    "total_incidents":   report.total_incidents,
                    "labeled_incidents": report.labeled_incidents,
                    "recommendations":   len(report.recommendations),
                    "generated_at":      report.generated_at.isoformat(),
                },
                tags=[self.agent_name, "learning_report"],
            )
            self.memory_provider.store(REPORTS_COLLECTION, record)
        except Exception as exc:
            logger.warning(
                "learning_report_store_failed",
                extra={"agent": self.agent_name, "error": str(exc)},
            )


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)
