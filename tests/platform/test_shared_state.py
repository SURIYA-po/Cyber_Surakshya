"""Tests for LangGraph shared state models."""

from tests.platform.conftest import (
    sample_alert,
    sample_analysis_result,
    sample_detection_result,
    sample_security_event,
)

from cyber_surakshya.platform.state import (
    PlatformStateModel,
    create_initial_state,
)


def test_create_initial_state_generates_ids():
    state = create_initial_state(metadata={"pipeline": "ids"})
    assert state.correlation_id
    assert state.trace_id
    assert state.session_id
    assert state.metadata["pipeline"] == "ids"
    assert state.security_events == []


def test_platform_state_round_trip_through_graph_state():
    state = create_initial_state()
    event = sample_security_event()
    detection = sample_detection_result(event)
    analysis = sample_analysis_result(event, detection)
    alert = sample_alert(event, detection)

    populated = state.model_copy(
        update={
            "security_events": [event],
            "detection_results": [detection],
            "analysis_results": [analysis],
            "alerts": [alert],
        }
    )

    graph_state = populated.to_graph_state()
    restored = PlatformStateModel.from_graph_state(graph_state)

    assert restored.correlation_id == populated.correlation_id
    assert len(restored.security_events) == 1
    assert len(restored.detection_results) == 1
    assert len(restored.analysis_results) == 1
    assert len(restored.alerts) == 1
    assert restored.security_events[0].event_id == event.event_id
    assert restored.analysis_results[0].detection_id == detection.detection_id
