"""Tests for LearningAgent: incident joining, feedback, reporting, boundaries."""
from __future__ import annotations

import pytest

from agents.learning import LearningAgent, OutcomeCollector
from agents.learning.exceptions import FeedbackStoreError
from cyber_surakshya.platform.schemas.learning_report import (
    AnalystVerdict,
    LearningReport,
    RecommendationType,
)
from tests.agents.learning_fixtures import (
    FakeMemoryProvider,
    analysis_record,
    decision_record,
    detection_record,
    response_record,
    seed_incident,
)


@pytest.fixture
def memory() -> FakeMemoryProvider:
    return FakeMemoryProvider()


@pytest.fixture
def agent(memory) -> LearningAgent:
    return LearningAgent(memory, min_sample_size=2)


# ── Outcome collection ────────────────────────────────────────────────────────


def test_full_chain_is_joined_into_one_incident(memory):
    detection_id = seed_incident(memory, entity_id="203.0.113.5")

    incidents = OutcomeCollector(memory).collect()

    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.detection_id == detection_id
    assert incident.analysis is not None
    assert incident.decision is not None
    assert len(incident.responses) == 1
    assert incident.is_complete is True
    assert incident.entity_id == "203.0.113.5"


def test_partial_chain_is_preserved_not_discarded(memory):
    """Discarding incomplete incidents would bias metrics toward fast cases."""
    seed_incident(memory, with_decision=False)

    incidents = OutcomeCollector(memory).collect()

    assert len(incidents) == 1
    assert incidents[0].is_complete is False
    assert incidents[0].decision is None


def test_one_correlation_id_with_many_events_yields_many_incidents(memory):
    """Since CoordinatorAgent, one run shares a correlation_id across events.

    Keying incidents on correlation_id would merge them and destroy every
    per-incident metric.
    """
    shared = "11111111-1111-4111-8111-111111111111"
    for index in range(3):
        detection = detection_record(
            correlation_id=shared, entity_id=f"203.0.113.{index}"
        )
        memory.store("detections", detection)
        memory.store("analysis", analysis_record(detection.content["detection_id"]))

    incidents = OutcomeCollector(memory).collect()

    assert len(incidents) == 3
    assert {i.correlation_id for i in incidents} == {shared}


def test_decision_linked_through_legacy_metadata(memory):
    """Records written before decision content carried detection_id still join."""
    detection = detection_record()
    detection_id = detection.content["detection_id"]
    memory.store("detections", detection)

    legacy = decision_record(detection_id)
    legacy.content.pop("detection_id")
    legacy.metadata = {"detection_id": detection_id}
    memory.store("decisions", legacy)

    incidents = OutcomeCollector(memory).collect()

    assert incidents[0].decision is not None


def test_awaiting_approval_is_not_a_terminal_response(memory):
    detection_id = seed_incident(memory, response_status="AWAITING_APPROVAL")

    incident = OutcomeCollector(memory).collect()[0]

    assert incident.detection_id == detection_id
    assert incident.responses
    assert incident.terminal_response is None
    assert incident.is_complete is False


def test_missing_collection_is_treated_as_empty(memory):
    """A fresh install has no feedback collection; the agent must still run."""
    seed_incident(memory)
    collector = OutcomeCollector(
        FakeMemoryProvider(fail_collections={"feedback", "approvals"})
    )

    assert collector.collect() == []


def test_empty_history_produces_an_empty_report_not_an_error(agent):
    report = agent.analyze(persist=False)

    assert isinstance(report, LearningReport)
    assert report.total_incidents == 0
    assert report.recommendations == []
    assert report.patterns == []


# ── Feedback ──────────────────────────────────────────────────────────────────


def test_feedback_round_trip(agent, memory):
    detection_id = seed_incident(memory)

    recorded = agent.record_feedback(
        detection_id=detection_id, verdict=AnalystVerdict.CORRECT, analyst="soc1"
    )
    fetched = agent.feedback_recorder.get(detection_id)

    assert recorded.detection_id == detection_id
    assert fetched is not None
    assert fetched.verdict is AnalystVerdict.CORRECT
    assert fetched.is_conclusive is True


def test_feedback_reaches_the_metrics_engine(agent, memory):
    detection_id = seed_incident(memory)
    assert agent.analyze(persist=False).labeled_incidents == 0

    agent.record_feedback(
        detection_id=detection_id, verdict=AnalystVerdict.CORRECT, analyst="soc1"
    )

    assert agent.analyze(persist=False).labeled_incidents == 1


def test_needs_review_is_not_counted_as_ground_truth(agent, memory):
    """"We don't know" must not be scored as either right or wrong."""
    detection_id = seed_incident(memory)
    agent.record_feedback(
        detection_id=detection_id, verdict=AnalystVerdict.NEEDS_REVIEW, analyst="soc1"
    )

    report = agent.analyze(persist=False)

    assert report.labeled_incidents == 0
    assert report.feedback_coverage == 0.0


def test_latest_verdict_wins_when_an_analyst_changes_their_mind(agent, memory):
    detection_id = seed_incident(memory)
    agent.record_feedback(
        detection_id=detection_id, verdict=AnalystVerdict.CORRECT, analyst="soc1"
    )
    agent.record_feedback(
        detection_id=detection_id, verdict=AnalystVerdict.INCORRECT, analyst="soc2"
    )

    incident = OutcomeCollector(memory).collect()[0]

    assert incident.feedback.verdict is AnalystVerdict.INCORRECT
    # Both rulings are retained — feedback is append-only history.
    assert len(memory.collections["feedback"]) == 2


def test_feedback_write_failure_is_raised_not_swallowed(memory):
    """Losing a verdict would corrupt every metric derived from it."""
    detection_id = seed_incident(memory)
    agent = LearningAgent(FakeMemoryProvider(fail_collections={"feedback"}))

    with pytest.raises(FeedbackStoreError):
        agent.record_feedback(
            detection_id=detection_id, verdict=AnalystVerdict.CORRECT, analyst="soc1"
        )


def test_string_verdicts_are_accepted(agent, memory):
    detection_id = seed_incident(memory)

    recorded = agent.record_feedback(
        detection_id=detection_id, verdict="false_positive", analyst="soc1"
    )

    assert recorded.verdict is AnalystVerdict.FALSE_POSITIVE


# ── Reporting ─────────────────────────────────────────────────────────────────


def test_report_is_persisted_for_trend_tracking(agent, memory):
    seed_incident(memory)

    report = agent.analyze(persist=True)

    stored = memory.collections["learning_reports"]
    assert len(stored) == 1
    assert stored[0].content["report_id"] == report.report_id
    assert agent.latest_report()["report_id"] == report.report_id


def test_report_storage_failure_does_not_fail_the_analysis(memory):
    """The report is already computed; losing the archived copy is survivable."""
    seed_incident(memory)
    failing = FakeMemoryProvider(fail_collections={"learning_reports"})
    failing.collections = memory.collections
    agent = LearningAgent(failing)

    report = agent.analyze(persist=True)

    assert report.total_incidents == 1


def test_report_counts_are_coherent(agent, memory):
    seed_incident(memory)
    seed_incident(memory, with_decision=False)

    report = agent.analyze(persist=False)

    assert report.total_incidents == 2
    assert report.complete_incidents == 1
    assert report.labeled_incidents <= report.total_incidents


def test_feedback_coverage_is_reported(agent, memory):
    first = seed_incident(memory, entity_id="203.0.113.1")
    seed_incident(memory, entity_id="203.0.113.2")
    agent.record_feedback(
        detection_id=first, verdict=AnalystVerdict.CORRECT, analyst="soc1"
    )

    assert agent.analyze(persist=False).feedback_coverage == 0.5


# ── Boundaries ────────────────────────────────────────────────────────────────


def test_agent_only_recommends_and_never_applies(agent, memory):
    """No module may retrain, edit policy, or execute an action."""
    for _ in range(6):
        seed_incident(memory, entity_id="203.0.113.99", predicted_label="DDOS")

    report = agent.analyze(persist=False)

    assert report.recommendations, "expected advisory output"
    for recommendation in report.recommendations:
        assert recommendation.suggested_change, "must describe a human action"
    # The agent exposes no apply/execute/retrain surface at all.
    for forbidden in ("apply", "execute", "retrain", "update_policy", "set_threshold"):
        assert not hasattr(agent, forbidden)


def test_graph_node_form_appends_no_results(agent, memory):
    from cyber_surakshya.platform.state import create_initial_state

    seed_incident(memory)

    update = agent(create_initial_state().to_graph_state())

    assert set(update) == {"correlation_id", "trace_id", "session_id", "metadata"}
    assert update["metadata"]["learning_agent"]["status"] == "completed"


def test_graph_node_form_contains_failures(memory):
    agent = LearningAgent(memory)
    agent.analyze = lambda **_: (_ for _ in ()).throw(RuntimeError("boom"))

    update = agent({"correlation_id": "11111111-1111-4111-8111-111111111111",
                    "trace_id": "11111111-1111-4111-8111-111111111111",
                    "session_id": "11111111-1111-4111-8111-111111111111"})

    assert update["errors"]
    assert update["metadata"]["learning_agent"]["status"] == "failed"


def test_platform_state_has_no_learning_reports_field():
    """A report describes history, not the run that produced it."""
    from cyber_surakshya.platform.state import PlatformStateModel

    assert "learning_reports" not in PlatformStateModel.model_fields
