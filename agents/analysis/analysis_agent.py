"""Analysis Agent LangGraph node."""

from __future__ import annotations

import logging
from typing import Any

from ai_engine.base import AIEngine, AnalysisContext
from cyber_surakshya.platform.schemas.analysis_result import AnalysisResult
from cyber_surakshya.platform.schemas.detection_result import DetectionResult
from cyber_surakshya.platform.schemas.security_event import SecurityEvent
from cyber_surakshya.platform.state import PlatformSharedState, PlatformStateModel
from memory.base import MemoryProvider
from memory.models import MemoryRecord

logger = logging.getLogger(__name__)


class AnalysisAgent:
    """
    LangGraph node that analyzes detection results.

    The agent performs reasoning only. It does not route, decide, respond,
    enrich with threat intelligence, map MITRE ATT&CK, or call LLM providers.
    """

    def __init__(
        self,
        ai_engine: AIEngine,
        *,
        memory_provider: MemoryProvider | None = None,
        agent_name: str = "analysis_agent",
    ) -> None:
        self.ai_engine = ai_engine
        self.memory_provider = memory_provider
        self.agent_name = agent_name

    def __call__(self, state: PlatformSharedState) -> PlatformSharedState:
        """Analyze one pending detection and return a state update."""
        try:
            state_model = PlatformStateModel.from_graph_state(state)
            detection = self._next_detection_for_analysis(state_model)
            if detection is None:
                logger.info(
                    "analysis_agent_no_pending_detections",
                    extra={
                        "agent": self.agent_name,
                        "correlation_id": state_model.correlation_id,
                        "trace_id": state_model.trace_id,
                        "session_id": state_model.session_id,
                    },
                )
                return self._metadata_update(
                    state_model,
                    status="skipped",
                    reason="no_pending_detection_results",
                )

            event = self._source_event_for_detection(state_model, detection)
            context = AnalysisContext(
                security_event=event,
                detection_result=detection,
                prior_analysis_count=len(state_model.analysis_results),
            )

            logger.info(
                "analysis_agent_started",
                extra={
                    "agent": self.agent_name,
                    "event_id": event.event_id,
                    "detection_id": detection.detection_id,
                    "correlation_id": state_model.correlation_id,
                    "trace_id": state_model.trace_id,
                },
            )

            analysis = self.ai_engine.analyze(context)
            analysis = self._link_analysis_to_state(
                analysis,
                event,
                detection,
                state_model,
            )
            self._store_memory(event, detection, analysis)

            logger.info(
                "analysis_agent_completed",
                extra={
                    "agent": self.agent_name,
                    "event_id": event.event_id,
                    "detection_id": detection.detection_id,
                    "analysis_id": analysis.analysis_id,
                    "confidence": analysis.confidence,
                },
            )
            return self._success_update(state_model, analysis, detection)
        except Exception as exc:
            logger.exception(
                "analysis_agent_failed",
                extra={"agent": self.agent_name, "error_type": type(exc).__name__},
            )
            return self._error_update(state, exc)

    def _next_detection_for_analysis(
        self,
        state: PlatformStateModel,
    ) -> DetectionResult | None:
        analyzed_detection_ids = {
            analysis.detection_id for analysis in state.analysis_results
        }
        for detection in state.detection_results:
            if detection.detection_id not in analyzed_detection_ids:
                return detection
        return None

    def _source_event_for_detection(
        self,
        state: PlatformStateModel,
        detection: DetectionResult,
    ) -> SecurityEvent:
        for event in state.security_events:
            if event.event_id == detection.event_id:
                return event
        raise ValueError(
            f"No SecurityEvent found for DetectionResult {detection.detection_id}."
        )

    def _link_analysis_to_state(
        self,
        analysis: AnalysisResult,
        event: SecurityEvent,
        detection: DetectionResult,
        state: PlatformStateModel,
    ) -> AnalysisResult:
        data = analysis.model_dump()
        data.update(
            {
                "event_id": event.event_id,
                "detection_id": detection.detection_id,
                "correlation_id": state.correlation_id,
                "trace_id": state.trace_id,
                "metadata": {
                    **analysis.metadata,
                    "agent": self.agent_name,
                    "source_event_id": event.event_id,
                    "source_detection_id": detection.detection_id,
                },
            }
        )
        return AnalysisResult.model_validate(data)

    def _store_memory(
        self,
        event: SecurityEvent,
        detection: DetectionResult,
        analysis: AnalysisResult,
    ) -> None:
        if self.memory_provider is None:
            return
        try:
            record = MemoryRecord(
                backend="qdrant_sqlite",
                collection="analysis",
                record_type="analysis_result",
                entity_id=self._entity_id_for_event(event),
                correlation_id=analysis.correlation_id,
                trace_id=analysis.trace_id,
                content={
                    "analysis_id": analysis.analysis_id,
                    "detection_id": detection.detection_id,
                    # The correlation keys the read model joins on. detection_id
                    # is the direct edge; event_id is the secondary key back to
                    # the SecurityEvent this whole chain describes.
                    "event_id": analysis.event_id,
                    "summary": analysis.summary,
                    "confidence": analysis.confidence,
                    # The AnalysisAgent's actual assessment, computed on every
                    # run and then discarded here — only summary and confidence
                    # were persisted. That is why the "AI Threat Analysis" panel
                    # had nothing to render and the frontend substituted a
                    # hardcoded recommendation list, identical for every alert.
                    "reasoning": analysis.reasoning,
                    "evidence": [
                        item.model_dump(mode="json") for item in analysis.evidence
                    ],
                    "uncertainty": list(analysis.uncertainty),
                    # The analysis layer's own risk verdict, which is a distinct
                    # judgement from the detector's and must not be conflated
                    # with it downstream.
                    "risk_score": analysis.risk_score.value,
                    "risk_level": (
                        analysis.risk_score.level.name
                        if analysis.risk_score.level
                        else None
                    ),
                    "risk_rationale": analysis.risk_score.rationale,
                    "severity_label": analysis.severity.name,
                    "severity_value": analysis.severity.value,
                    # Provenance: deterministic rules and an LLM engine reach
                    # very different assessments, and the dashboard should be
                    # able to say which one it is showing.
                    "analysis_engine": type(self.ai_engine).__name__,
                    # Stage timestamp for LearningAgent pipeline-latency metrics.
                    "analyzed_at": analysis.analyzed_at.isoformat(),
                },
                metadata={
                    "agent": self.agent_name,
                    "severity": analysis.severity.value,
                    "severity_label": analysis.severity.name,
                    # Join keys: detection_id is the edge this record hangs
                    # from, analysis_id the edge DecisionResult hangs from.
                    "detection_id": detection.detection_id,
                    "analysis_id": analysis.analysis_id,
                    "event_id": analysis.event_id,
                    "source": event.source.value,
                },
                tags=[self.agent_name, "analysis"],
            )
            self.memory_provider.store("analysis", record)
        except Exception as exc:
            logger.warning(
                "analysis_agent_memory_store_failed",
                extra={"agent": self.agent_name, "error": str(exc)},
            )

    def _entity_id_for_event(self, event: SecurityEvent) -> str | None:
        if event.network and event.network.source_ip:
            return event.network.source_ip
        return event.event_id

    def _success_update(
        self,
        state: PlatformStateModel,
        analysis: AnalysisResult,
        detection: DetectionResult,
    ) -> PlatformSharedState:
        metadata = self._merged_metadata(
            state,
            {
                "status": "completed",
                "last_detection_id": detection.detection_id,
                "last_analysis_id": analysis.analysis_id,
                "analysis_count": len(state.analysis_results) + 1,
                "engine": type(self.ai_engine).__name__,
            },
        )
        return PlatformSharedState(
            correlation_id=state.correlation_id,
            trace_id=state.trace_id,
            session_id=state.session_id,
            analysis_results=[analysis],
            metadata=metadata,
        )

    def _metadata_update(
        self,
        state: PlatformStateModel,
        *,
        status: str,
        reason: str,
    ) -> PlatformSharedState:
        return PlatformSharedState(
            correlation_id=state.correlation_id,
            trace_id=state.trace_id,
            session_id=state.session_id,
            metadata=self._merged_metadata(
                state,
                {
                    "status": status,
                    "reason": reason,
                    "analysis_count": len(state.analysis_results),
                    "engine": type(self.ai_engine).__name__,
                },
            ),
        )

    def _error_update(
        self,
        state: PlatformSharedState,
        error: Exception,
    ) -> PlatformSharedState:
        failure = {
            "status": "failed",
            "error_type": type(error).__name__,
            "engine": type(self.ai_engine).__name__,
        }
        # `state` is the raw graph TypedDict, never a PlatformStateModel, so
        # the old isinstance guard always nulled these identifiers and the
        # run failed validation on exit — one agent error killed the run.
        try:
            state_model = PlatformStateModel.from_graph_state(state)
            metadata = self._merged_metadata(state_model, failure)
            correlation_id = state_model.correlation_id
            trace_id = state_model.trace_id
            session_id = state_model.session_id
        except Exception:
            metadata = {self.agent_name: failure}
            raw = state if isinstance(state, dict) else {}
            correlation_id = raw.get("correlation_id")
            trace_id = raw.get("trace_id")
            session_id = raw.get("session_id")

        update: PlatformSharedState = {
            "errors": [f"{self.agent_name}: {error}"],
            "metadata": metadata,
        }
        if correlation_id is not None:
            update["correlation_id"] = correlation_id
        if trace_id is not None:
            update["trace_id"] = trace_id
        if session_id is not None:
            update["session_id"] = session_id
        return update

    def _merged_metadata(
        self,
        state: PlatformStateModel,
        analysis_metadata: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            **state.metadata,
            self.agent_name: analysis_metadata,
        }
