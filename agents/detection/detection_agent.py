"""Detection Agent LangGraph node."""

from __future__ import annotations

import logging
from typing import Any

from adapters.detection.ids_adapter import IDSDetectionAdapter
from cyber_surakshya.platform.schemas.detection_result import DetectionResult
from cyber_surakshya.platform.schemas.security_event import SecurityEvent
from cyber_surakshya.platform.state import PlatformSharedState, PlatformStateModel
from memory.base import MemoryProvider
from memory.models import MemoryRecord

logger = logging.getLogger(__name__)


class DetectionAgent:
    """
    LangGraph node that runs IDS detection for incoming security events.

    The agent only performs detection. It does not route, analyze, decide,
    respond, enrich with threat intelligence, or call LLMs.
    """

    def __init__(
        self,
        ids_adapter: IDSDetectionAdapter,
        *,
        memory_provider: MemoryProvider | None = None,
        agent_name: str = "detection_agent",
    ) -> None:
        self.ids_adapter = ids_adapter
        self.memory_provider = memory_provider
        self.agent_name = agent_name

    def __call__(self, state: PlatformSharedState) -> PlatformSharedState:
        """Process one pending security event and return a state update."""
        try:
            state_model = PlatformStateModel.from_graph_state(state)
            event = self._next_event_for_detection(state_model)
            if event is None:
                logger.info(
                    "detection_agent_no_pending_events",
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
                    reason="no_pending_security_events",
                )

            flow_data = self._extract_flow_data(event)
            logger.info(
                "detection_agent_started",
                extra={
                    "agent": self.agent_name,
                    "event_id": event.event_id,
                    "correlation_id": state_model.correlation_id,
                    "trace_id": state_model.trace_id,
                    "feature_count": len(flow_data),
                },
            )

            detection = self.ids_adapter.detect(flow_data)
            detection = self._link_detection_to_state(detection, event, state_model)
            self._store_memory(event, detection)

            logger.info(
                "detection_agent_completed",
                extra={
                    "agent": self.agent_name,
                    "event_id": event.event_id,
                    "detection_id": detection.detection_id,
                    "status": detection.status.value,
                    "predicted_label": detection.predicted_label,
                    "confidence": detection.confidence,
                },
            )
            return self._success_update(state_model, detection, event)
        except Exception as exc:
            logger.exception(
                "detection_agent_failed",
                extra={"agent": self.agent_name, "error_type": type(exc).__name__},
            )
            return self._error_update(state, exc)

    def _next_event_for_detection(
        self,
        state: PlatformStateModel,
    ) -> SecurityEvent | None:
        detected_event_ids = {
            detection.event_id for detection in state.detection_results
        }
        for event in state.security_events:
            if event.event_id not in detected_event_ids:
                return event
        return None

    def _extract_flow_data(self, event: SecurityEvent) -> dict[str, Any]:
        if event.features:
            return dict(event.features)
        if event.raw_payload:
            return dict(event.raw_payload)
        raise ValueError(
            f"SecurityEvent {event.event_id} has no features or raw_payload for detection."
        )

    def _link_detection_to_state(
        self,
        detection: DetectionResult,
        event: SecurityEvent,
        state: PlatformStateModel,
    ) -> DetectionResult:
        data = detection.model_dump()
        data.update(
            {
                "event_id": event.event_id,
                "correlation_id": state.correlation_id,
                "trace_id": state.trace_id,
                "metadata": {
                    **detection.metadata,
                    "agent": self.agent_name,
                    "source_event_id": event.event_id,
                },
            }
        )
        return DetectionResult.model_validate(data)

    def _store_memory(
        self,
        event: SecurityEvent,
        detection: DetectionResult,
    ) -> None:
        if self.memory_provider is None:
            return
        try:
            record = MemoryRecord(
                backend="qdrant_sqlite",
                collection="detections",
                record_type="detection_result",
                entity_id=self._entity_id_for_event(event),
                correlation_id=detection.correlation_id,
                trace_id=detection.trace_id,
                content={
                    "event_id": event.event_id,
                    "detection_id": detection.detection_id,
                    "predicted_label": detection.predicted_label,
                    "confidence": detection.confidence,
                    "status": detection.status.value,
                    # Stage timestamps make time-to-detect measurable by
                    # LearningAgent. Without observed_at persisted here, MTTD
                    # cannot be computed from history at all.
                    "observed_at": event.observed_at.isoformat(),
                    "ingested_at": event.ingested_at.isoformat(),
                    "detected_at": detection.detected_at.isoformat(),
                    "risk_score": detection.risk_score.value,
                    # The band and the adapter's own explanation of how the
                    # score was reached. Persisting the bare number alone left
                    # the API with nothing to justify it, so the dashboard
                    # re-derived its own bands and its own colour thresholds
                    # and drifted from RISK_BANDS.
                    "risk_level": (
                        detection.risk_score.level.name
                        if detection.risk_score.level
                        else None
                    ),
                    "risk_rationale": detection.risk_score.rationale,
                    # Both representations, under distinct keys. `severity` in
                    # this record's *metadata* remains the IntEnum ordinal that
                    # existing consumers read; the label is additive.
                    "severity_label": detection.severity.name,
                    "severity_value": detection.severity.value,
                    # The unsupervised layer's verdict. BENIGN + is_anomaly is
                    # the INCONCLUSIVE case: the reason a flow the classifier
                    # called benign can still be worth an analyst's time.
                    "is_anomaly": detection.is_anomaly,
                    # Provenance. Which detector produced this, so an
                    # assessment stays attributable once Zeek/Suricata/host
                    # adapters write into the same collection.
                    "detection_source": detection.metadata.get("adapter"),
                    "model_name": detection.model_name,
                    "model_version": detection.model_version,
                },
                metadata={
                    "agent": self.agent_name,
                    "severity": detection.severity.value,
                    "severity_label": detection.severity.name,
                    # The domain identifiers, in metadata so the read model can
                    # query for a detection by its detection_id. The memory
                    # primary key is a separate uuid, so without these a lookup
                    # by detection_id could only be done by scanning.
                    "detection_id": detection.detection_id,
                    "event_id": event.event_id,
                    "source": event.source.value,
                },
                tags=[self.agent_name, "detection"],
            )
            self.memory_provider.store("detections", record)
        except Exception as exc:
            logger.warning(
                "detection_agent_memory_store_failed",
                extra={"agent": self.agent_name, "error": str(exc)},
            )

    def _entity_id_for_event(self, event: SecurityEvent) -> str | None:
        if event.network and event.network.source_ip:
            return event.network.source_ip
        return event.event_id

    def _success_update(
        self,
        state: PlatformStateModel,
        detection: DetectionResult,
        event: SecurityEvent,
    ) -> PlatformSharedState:
        metadata = self._merged_metadata(
            state,
            {
                "status": "completed",
                "last_event_id": event.event_id,
                "last_detection_id": detection.detection_id,
                "detection_count": len(state.detection_results) + 1,
                "adapter": type(self.ids_adapter).__name__,
            },
        )
        return PlatformSharedState(
            correlation_id=state.correlation_id,
            trace_id=state.trace_id,
            session_id=state.session_id,
            detection_results=[detection],
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
                    "detection_count": len(state.detection_results),
                    "adapter": type(self.ids_adapter).__name__,
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
            "adapter": type(self.ids_adapter).__name__,
        }
        # `state` is the raw graph state, never a PlatformStateModel — the
        # previous `isinstance(state, PlatformStateModel)` guard was therefore
        # always False and nulled all three identifiers. The run then failed
        # PlatformStateModel validation on the way out of the graph, so a
        # single agent error took down the whole run instead of being
        # recorded as one entry in `errors`.
        try:
            state_model = PlatformStateModel.from_graph_state(state)
            metadata = self._merged_metadata(state_model, failure)
            correlation_id = state_model.correlation_id
            trace_id = state_model.trace_id
            session_id = state_model.session_id
        except Exception:
            # State itself is unparseable. Fall back to the raw keys so the
            # error still carries its correlation context where possible.
            metadata = {self.agent_name: failure}
            raw = state if isinstance(state, dict) else {}
            correlation_id = raw.get("correlation_id")
            trace_id = raw.get("trace_id")
            session_id = raw.get("session_id")

        update: PlatformSharedState = {
            "errors": [f"{self.agent_name}: {error}"],
            "metadata": metadata,
        }
        # Omitted rather than set to None: these are non-optional strings on
        # PlatformStateModel, and LangGraph merges only the keys present.
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
        detection_metadata: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            **state.metadata,
            self.agent_name: detection_metadata,
        }
