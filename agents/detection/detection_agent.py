"""Detection Agent LangGraph node."""

from __future__ import annotations

import logging
from typing import Any

from adapters.detection.ids_adapter import IDSDetectionAdapter
from cyber_surakshya.platform.schemas.detection_result import DetectionResult
from cyber_surakshya.platform.schemas.security_event import SecurityEvent
from cyber_surakshya.platform.state import PlatformSharedState, PlatformStateModel

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
        agent_name: str = "detection_agent",
    ) -> None:
        self.ids_adapter = ids_adapter
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
            metadata=self._merged_metadata(
                state,
                {
                    "status": status,
                    "reason": reason,
                    "detection_count": len(state.detection_results),
                    "adapter": type(self.ids_adapter).__name__,
                },
            )
        )

    def _error_update(
        self,
        state: PlatformSharedState,
        error: Exception,
    ) -> PlatformSharedState:
        try:
            state_model = PlatformStateModel.from_graph_state(state)
            metadata = self._merged_metadata(
                state_model,
                {
                    "status": "failed",
                    "error_type": type(error).__name__,
                    "adapter": type(self.ids_adapter).__name__,
                },
            )
        except Exception:
            metadata = {
                "detection_agent": {
                    "status": "failed",
                    "error_type": type(error).__name__,
                    "adapter": type(self.ids_adapter).__name__,
                }
            }
        return PlatformSharedState(
            errors=[f"{self.agent_name}: {error}"],
            metadata=metadata,
        )

    def _merged_metadata(
        self,
        state: PlatformStateModel,
        detection_metadata: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            **state.metadata,
            self.agent_name: detection_metadata,
        }
