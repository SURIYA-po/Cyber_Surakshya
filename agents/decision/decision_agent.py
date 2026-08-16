"""Decision Agent LangGraph node.

Responsibilities (strict boundary):
  DOES:
    - Read AnalysisResult + DetectionResult from PlatformSharedState
    - Query MemoryProvider for historical entity records (optional)
    - Delegate to DecisionEngine.make_decision(DecisionContext)
    - Append one validated DecisionResult to state.decision_results

  DOES NOT:
    - Execute firewall rules, iptables, or cloud security group changes
    - Isolate hosts, terminate connections, or block IPs
    - Send Slack/email/webhook notifications
    - Read or produce ResponseResult
    - Perform graph routing, coordination, or state branching

ResponseAgent (future) reads DecisionResult exclusively. It never
reads AnalysisResult or DetectionResult.
"""
from __future__ import annotations

import logging
import time
from typing import Any

from agents.decision.base import DecisionContext, DecisionEngine
from agents.decision.exceptions import (
    MissingDetectionError,
    MissingEventError,
)
from cyber_surakshya.platform.audit.metadata import AuditMetadata
from cyber_surakshya.platform.schemas.analysis_result import AnalysisResult
from cyber_surakshya.platform.schemas.decision_result import (
    DecisionResult,
    DecisionStatus,
)
from cyber_surakshya.platform.schemas.detection_result import DetectionResult
from cyber_surakshya.platform.schemas.security_event import SecurityEvent
from cyber_surakshya.platform.state import PlatformSharedState, PlatformStateModel
from memory.base import MemoryProvider
from memory.models import MemoryQuery, MemoryRecord

logger = logging.getLogger(__name__)

# Memory collection names — shared constants (no invented schema).
_THREAT_COLLECTION = "threat_history"


class DecisionAgent:
    """LangGraph node that evaluates policy and produces a DecisionResult.

    Injected dependencies (constructor):
      - ``decision_engine``  — implements DecisionEngine Protocol.
      - ``memory_provider``  — implements MemoryProvider Protocol (optional).

    DecisionAgent never imports concrete implementations; all are injected
    at startup (via app.py::ensure_runtime).
    """

    def __init__(
        self,
        decision_engine: DecisionEngine,
        *,
        memory_provider: MemoryProvider | None = None,
        agent_name: str = "decision_agent",
    ) -> None:
        self.decision_engine = decision_engine
        self.memory_provider = memory_provider
        self.agent_name      = agent_name

    def __call__(self, state: PlatformSharedState) -> PlatformSharedState:
        """Evaluate one pending AnalysisResult and return a state update."""
        try:
            state_model = PlatformStateModel.from_graph_state(state)
            analysis    = self._next_analysis_for_decision(state_model)

            if analysis is None:
                logger.info(
                    "decision_agent_no_pending_analysis",
                    extra={
                        "agent":          self.agent_name,
                        "correlation_id": state_model.correlation_id,
                        "trace_id":       state_model.trace_id,
                        "session_id":     state_model.session_id,
                    },
                )
                return self._metadata_update(
                    state_model,
                    status="skipped",
                    reason="no_pending_analysis_results",
                )

            detection = self._source_detection(state_model, analysis)
            event     = self._source_event(state_model, detection)

            logger.info(
                "decision_agent_started",
                extra={
                    "agent":          self.agent_name,
                    "analysis_id":    analysis.analysis_id,
                    "detection_id":   detection.detection_id,
                    "event_id":       event.event_id,
                    "correlation_id": state_model.correlation_id,
                    "trace_id":       state_model.trace_id,
                },
            )

            historical = self._query_memory(event)
            context = DecisionContext(
                security_event=event,
                detection_result=detection,
                analysis_result=analysis,
                historical_records=historical,
                prior_decision_count=len(state_model.decision_results),
            )

            t0          = time.perf_counter()
            draft       = self.decision_engine.make_decision(context)
            duration_ms = (time.perf_counter() - t0) * 1000.0

            result = self._build_result(
                draft, analysis, detection, event, state_model, duration_ms,
            )
            self._store_memory(event, analysis, detection, result)

            logger.info(
                "decision_agent_completed",
                extra={
                    "agent":             self.agent_name,
                    "decision_id":       result.decision_id,
                    "action_type":       result.action.action_type.value,
                    "priority":          result.priority.value,
                    "requires_approval": result.requires_approval,
                    "approval_status":   result.approval_status.value,
                    "duration_ms":       round(duration_ms, 2),
                    "memory_hits":       result.memory_hits,
                    "policy_name":       result.policy_name,
                },
            )
            return self._success_update(state_model, result, analysis)

        except Exception as exc:
            logger.exception(
                "decision_agent_failed",
                extra={
                    "agent":      self.agent_name,
                    "error_type": type(exc).__name__,
                },
            )
            return self._error_update(state, exc)

    # ── State traversal ───────────────────────────────────────────────────────

    def _next_analysis_for_decision(
        self,
        state: PlatformStateModel,
    ) -> AnalysisResult | None:
        """Return the first AnalysisResult without a corresponding DecisionResult."""
        decided_analysis_ids = {d.analysis_id for d in state.decision_results}
        for analysis in state.analysis_results:
            if analysis.analysis_id not in decided_analysis_ids:
                return analysis
        return None

    def _source_detection(
        self,
        state: PlatformStateModel,
        analysis: AnalysisResult,
    ) -> DetectionResult:
        """Find the DetectionResult that produced the given AnalysisResult."""
        for det in state.detection_results:
            if det.detection_id == analysis.detection_id:
                return det
        raise MissingDetectionError(
            f"No DetectionResult found for AnalysisResult "
            f"{analysis.analysis_id!r} (detection_id={analysis.detection_id!r})."
        )

    def _source_event(
        self,
        state: PlatformStateModel,
        detection: DetectionResult,
    ) -> SecurityEvent:
        """Find the SecurityEvent that produced the given DetectionResult."""
        for ev in state.security_events:
            if ev.event_id == detection.event_id:
                return ev
        raise MissingEventError(
            f"No SecurityEvent found for DetectionResult "
            f"{detection.detection_id!r} (event_id={detection.event_id!r})."
        )

    # ── Memory ────────────────────────────────────────────────────────────────

    def _query_memory(self, event: SecurityEvent) -> list:
        """Query MemoryProvider for prior incident records for this entity.

        Returns an empty list when no MemoryProvider is injected or when
        the query fails (failure is logged as a warning, never re-raised).
        Uses MemoryQuery with record_types and entity_ids — no invented
        collection schemas.
        """
        if self.memory_provider is None:
            return []
        try:
            entity_id = self._extract_entity_id(event)
            query = MemoryQuery(
                query_text=None,
                record_types=["threat_event"],
                entity_ids=[entity_id],
                tags=["decision_agent"],
                limit=10,
            )
            return self.memory_provider.search(_THREAT_COLLECTION, query)
        except Exception as exc:
            logger.warning(
                "decision_agent_memory_query_failed",
                extra={"error": str(exc), "agent": self.agent_name},
            )
            return []

    @staticmethod
    def _extract_entity_id(event: SecurityEvent) -> str:
        """Extract the best available entity identifier from a security event."""
        network = getattr(event, "network", None)
        if network is not None:
            source_ip = getattr(network, "source_ip", None)
            if source_ip:
                return source_ip
        return event.event_id

    # ── Result construction ───────────────────────────────────────────────────

    def _store_memory(
        self,
        event: SecurityEvent,
        analysis: AnalysisResult,
        detection: DetectionResult,
        result: DecisionResult,
    ) -> None:
        if self.memory_provider is None:
            return
        try:
            record = MemoryRecord(
                backend="qdrant_sqlite",
                collection="decisions",
                record_type="decision_result",
                entity_id=self._extract_entity_id(event),
                correlation_id=result.correlation_id,
                trace_id=result.trace_id,
                content={
                    "decision_id": result.decision_id,
                    "analysis_id": analysis.analysis_id,
                    "detection_id": detection.detection_id,
                    "event_id": result.event_id,
                    "action_type": result.action.action_type.value,
                    # What the action is aimed at. Without the target, a
                    # persisted decision says "block" without saying "block
                    # what", and the dashboard cannot show the recommendation
                    # without re-deriving it from the alert.
                    "action_target_type": result.action.target.target_type,
                    "action_target_value": result.action.target.target_value,
                    "priority": result.priority.value,
                    "status": result.status.value,
                    "requires_approval": result.requires_approval,
                    "approval_status": result.approval_status.value,
                    "confidence": result.confidence,
                    # The engine's stated reason for this action. Dropping it
                    # meant the frontend had no recommendation text to show, so
                    # it shipped five hardcoded strings — including "Block the
                    # source IP immediately" on benign alerts.
                    "rationale": result.rationale,
                    "policy_name": result.policy_name,
                    "policy_version": result.policy_version,
                    # Provenance: which engine decided, and at what version.
                    "decision_engine": result.decision_engine,
                    "engine_version": result.engine_version,
                    "memory_hits": result.memory_hits,
                    # Stage timestamp for LearningAgent pipeline-latency metrics.
                    "decided_at": result.decided_at.isoformat(),
                },
                metadata={
                    "agent": self.agent_name,
                    "analysis_id": analysis.analysis_id,
                    "detection_id": detection.detection_id,
                    # The edge ResponseResult hangs from, completing the
                    # detection -> analysis -> decision -> response chain in
                    # metadata so each hop is a query rather than a scan.
                    "decision_id": result.decision_id,
                    "event_id": result.event_id,
                    "policy": result.policy_name,
                },
                tags=[self.agent_name, "decision"],
            )
            self.memory_provider.store("decisions", record)
        except Exception as exc:
            logger.warning(
                "decision_agent_memory_store_failed",
                extra={"agent": self.agent_name, "error": str(exc)},
            )

    def _build_result(
        self,
        draft: Any,
        analysis: AnalysisResult,
        detection: DetectionResult,
        event: SecurityEvent,
        state: PlatformStateModel,
        duration_ms: float,
    ) -> DecisionResult:
        """Convert a DecisionDraft to a fully-linked, validated DecisionResult."""
        status = (
            DecisionStatus.WAITING_APPROVAL
            if draft.requires_approval
            else DecisionStatus.READY_FOR_EXECUTION
        )
        return DecisionResult(
            analysis_id=analysis.analysis_id,
            detection_id=detection.detection_id,
            event_id=event.event_id,
            correlation_id=state.correlation_id,
            trace_id=state.trace_id,
            action=draft.action,
            priority=draft.priority,
            status=status,
            requires_approval=draft.requires_approval,
            approval_status=draft.approval_status,
            rationale=draft.rationale,
            confidence=draft.confidence,
            policy_version=self.decision_engine.policy_version,
            decision_engine=self.decision_engine.engine_name,
            engine_version=self.decision_engine.engine_version,
            policy_name=draft.policy_name,
            decision_duration_ms=round(duration_ms, 3),
            memory_hits=draft.memory_hits,
            metadata={
                "agent":               self.agent_name,
                "source_analysis_id":  analysis.analysis_id,
                "source_detection_id": detection.detection_id,
                "source_event_id":     event.event_id,
            },
            audit=AuditMetadata(
                created_by=self.agent_name,
                updated_by=self.agent_name,
                source_system="decision_pipeline",
            ),
        )

    # ── State update helpers (mirrors AnalysisAgent pattern) ─────────────────

    def _success_update(
        self,
        state: PlatformStateModel,
        result: DecisionResult,
        analysis: AnalysisResult,
    ) -> PlatformSharedState:
        metadata = self._merged_metadata(
            state,
            {
                "status":             "completed",
                "last_analysis_id":   analysis.analysis_id,
                "last_decision_id":   result.decision_id,
                "decision_count":     len(state.decision_results) + 1,
                "engine":             self.decision_engine.engine_name,
                "action_type":        result.action.action_type.value,
                "requires_approval":  result.requires_approval,
                "approval_status":    result.approval_status.value,
                "policy_name":        result.policy_name,
            },
        )
        return PlatformSharedState(
            correlation_id=state.correlation_id,
            trace_id=state.trace_id,
            session_id=state.session_id,
            decision_results=[result],
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
                    "engine": self.decision_engine.engine_name,
                    "decision_count": len(state.decision_results),
                },
            ),
        )

    def _error_update(
        self,
        state: PlatformSharedState,
        error: Exception,
    ) -> PlatformSharedState:
        failure = {
            "status":     "failed",
            "error_type": type(error).__name__,
            "engine":     self.decision_engine.engine_name,
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
        decision_metadata: dict[str, Any],
    ) -> dict[str, Any]:
        return {**state.metadata, self.agent_name: decision_metadata}
