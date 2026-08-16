"""Tests for MetricsEngine, PatternDiscovery, and RecommendationEngine.

The arithmetic here decides whether a human retrains a model or loosens a
detection threshold, so the evidence guards are tested as hard as the values.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from agents.learning import (
    LearningAgent,
    MetricsEngine,
    OutcomeCollector,
    PatternDiscovery,
    RecommendationEngine,
)
from agents.learning.pattern_discovery import PatternThresholds
from cyber_surakshya.platform.schemas.learning_report import (
    AnalystVerdict,
    PatternType,
    RecommendationType,
)
from tests.agents.learning_fixtures import BASE_TIME, FakeMemoryProvider, seed_incident


def _incidents(memory: FakeMemoryProvider):
    return OutcomeCollector(memory).collect()


def _metric(memory: FakeMemoryProvider, name: str, *, min_sample_size: int = 2):
    metrics = MetricsEngine(min_sample_size=min_sample_size).compute(_incidents(memory))
    return next(m for m in metrics if m.name == name)


@pytest.fixture
def memory() -> FakeMemoryProvider:
    return FakeMemoryProvider()


# ── Evidence guards ───────────────────────────────────────────────────────────


def test_ground_truth_metrics_are_none_without_any_feedback(memory):
    for index in range(20):
        seed_incident(memory, entity_id=f"203.0.113.{index}")

    for name in (
        "false_positive_rate", "false_negative_rate",
        "precision", "recall", "detection_accuracy", "decision_accuracy",
    ):
        metric = _metric(memory, name)
        assert metric.value is None, name
        assert metric.sufficient_data is False, name
        assert metric.sample_size == 0, name


def test_metric_below_sample_floor_reports_no_value(memory):
    agent = LearningAgent(memory, min_sample_size=10)
    for index in range(3):
        detection_id = seed_incident(memory, entity_id=f"203.0.113.{index}")
        agent.record_feedback(
            detection_id=detection_id, verdict=AnalystVerdict.CORRECT, analyst="soc"
        )

    metric = _metric(memory, "detection_accuracy", min_sample_size=10)

    assert metric.value is None
    assert metric.sufficient_data is False
    assert metric.sample_size == 3
    assert "needs 10" in metric.detail


def test_metric_at_the_floor_reports_a_value(memory):
    agent = LearningAgent(memory, min_sample_size=2)
    for index in range(2):
        detection_id = seed_incident(memory, entity_id=f"203.0.113.{index}")
        agent.record_feedback(
            detection_id=detection_id, verdict=AnalystVerdict.CORRECT, analyst="soc"
        )

    metric = _metric(memory, "detection_accuracy")

    assert metric.value == 1.0
    assert metric.sufficient_data is True


def test_min_sample_size_must_be_positive():
    with pytest.raises(ValueError):
        MetricsEngine(min_sample_size=0)


# ── Confusion matrix ──────────────────────────────────────────────────────────


def test_false_positive_is_a_rejected_threat_detection(memory):
    agent = LearningAgent(memory, min_sample_size=2)
    confirmed = seed_incident(memory, entity_id="203.0.113.1", status="detected")
    rejected  = seed_incident(memory, entity_id="203.0.113.2", status="detected")
    agent.record_feedback(detection_id=confirmed, verdict=AnalystVerdict.CORRECT, analyst="s")
    agent.record_feedback(
        detection_id=rejected, verdict=AnalystVerdict.FALSE_POSITIVE, analyst="s"
    )

    assert _metric(memory, "false_positive_rate").value == 0.5
    assert _metric(memory, "precision").value == 0.5


def test_false_negative_is_a_rejected_benign_detection(memory):
    agent = LearningAgent(memory, min_sample_size=2)
    right = seed_incident(
        memory, entity_id="203.0.113.1", predicted_label="BENIGN", status="benign"
    )
    missed = seed_incident(
        memory, entity_id="203.0.113.2", predicted_label="BENIGN", status="benign"
    )
    agent.record_feedback(detection_id=right, verdict=AnalystVerdict.CORRECT, analyst="s")
    agent.record_feedback(detection_id=missed, verdict=AnalystVerdict.INCORRECT, analyst="s")

    assert _metric(memory, "false_negative_rate").value == 1.0
    assert _metric(memory, "detection_accuracy").value == 0.5


def test_escalate_on_a_threat_counts_as_correct(memory):
    agent = LearningAgent(memory, min_sample_size=1)
    detection_id = seed_incident(memory, status="detected")
    agent.record_feedback(
        detection_id=detection_id, verdict=AnalystVerdict.ESCALATE, analyst="s"
    )

    assert _metric(memory, "precision", min_sample_size=1).value == 1.0


def test_contradictory_verdict_is_excluded_not_reinterpreted(memory):
    """FALSE_POSITIVE on a benign detection is contradictory input.

    Nothing was flagged, so there is no positive to be false. Folding it into
    the false-negative count would invert the analyst's meaning.
    """
    agent = LearningAgent(memory, min_sample_size=1)
    contradictory = seed_incident(
        memory, entity_id="203.0.113.1", predicted_label="BENIGN", status="benign"
    )
    sane = seed_incident(
        memory, entity_id="203.0.113.2", predicted_label="BENIGN", status="benign"
    )
    agent.record_feedback(
        detection_id=contradictory, verdict=AnalystVerdict.FALSE_POSITIVE, analyst="s"
    )
    agent.record_feedback(detection_id=sane, verdict=AnalystVerdict.CORRECT, analyst="s")

    accuracy = _metric(memory, "detection_accuracy", min_sample_size=1)

    assert accuracy.sample_size == 1, "the contradictory ruling is excluded"
    assert accuracy.value == 1.0
    # With the contradictory ruling removed there are no actual threats left,
    # so the miss rate has an empty denominator and is undefined — not zero.
    miss_rate = _metric(memory, "false_negative_rate", min_sample_size=1)
    assert miss_rate.value is None
    assert "across 0 actual threat(s)" in miss_rate.detail


# ── Timing ────────────────────────────────────────────────────────────────────


def test_mttd_and_mttr_measure_from_observation(memory):
    seed_incident(memory, detect_seconds=3.0, respond_seconds=11.0)

    assert _metric(memory, "mttd_seconds").value == 3.0
    assert _metric(memory, "mttr_seconds").value == 11.0


def test_records_without_timestamps_are_excluded_not_zeroed(memory):
    """Defaulting to zero would report a flawless MTTD built from missing data."""
    seed_incident(memory, entity_id="203.0.113.1", observed_at=None)

    metric = _metric(memory, "mttd_seconds")

    assert metric.value is None
    assert metric.sample_size == 0
    assert metric.sufficient_data is False
    assert "excluded" in metric.detail


def test_mttd_averages_only_measurable_incidents(memory):
    seed_incident(memory, entity_id="203.0.113.1", detect_seconds=2.0)
    seed_incident(memory, entity_id="203.0.113.2", detect_seconds=4.0)
    seed_incident(memory, entity_id="203.0.113.3", observed_at=None)

    metric = _metric(memory, "mttd_seconds")

    assert metric.value == 3.0
    assert metric.sample_size == 2


# ── Response layer ────────────────────────────────────────────────────────────


def test_awaiting_approval_is_not_a_response_failure(memory):
    """The safety layer working as designed must not look like a failure.

    Counting it as one would push the recommendation engine toward loosening
    the very gates that are working.
    """
    seed_incident(memory, entity_id="203.0.113.1", response_status="EXECUTED")
    seed_incident(memory, entity_id="203.0.113.2", response_status="AWAITING_APPROVAL")
    seed_incident(memory, entity_id="203.0.113.3", response_status="BLOCKED_BY_GUARD")

    metric = _metric(memory, "response_success_rate")

    assert metric.value == 1.0
    assert metric.sample_size == 1


def test_failed_response_lowers_the_success_rate(memory):
    seed_incident(memory, entity_id="203.0.113.1", response_status="EXECUTED")
    seed_incident(memory, entity_id="203.0.113.2", response_status="FAILED")

    assert _metric(memory, "response_success_rate").value == 0.5


def test_approval_rate_counts_rulings(memory):
    seed_incident(memory, entity_id="203.0.113.1", approved=True)
    seed_incident(memory, entity_id="203.0.113.2", approved=False)
    seed_incident(memory, entity_id="203.0.113.3")     # no ruling

    metric = _metric(memory, "approval_rate")

    assert metric.value == 0.5
    assert metric.sample_size == 2


def test_guard_intervention_rate(memory):
    seed_incident(memory, entity_id="203.0.113.1", response_status="EXECUTED")
    seed_incident(memory, entity_id="203.0.113.2", response_status="DOWNGRADED")

    assert _metric(memory, "guard_intervention_rate").value == 0.5


# ── Patterns ──────────────────────────────────────────────────────────────────


def test_repeat_attacker_requires_the_threshold(memory):
    for _ in range(2):
        seed_incident(memory, entity_id="203.0.113.7")
    assert not _patterns(memory, PatternType.REPEAT_ATTACKER)

    seed_incident(memory, entity_id="203.0.113.7")
    found = _patterns(memory, PatternType.REPEAT_ATTACKER)

    assert found and found[0].occurrences == 3
    assert found[0].entities == ["203.0.113.7"]


def test_recurring_incident_flags_containment_that_is_not_holding(memory):
    for _ in range(3):
        seed_incident(memory, entity_id="203.0.113.8", predicted_label="DDOS")

    found = _patterns(memory, PatternType.RECURRING_INCIDENT)

    assert found and "not be holding" in found[0].summary


def test_repeated_response_failure_is_detected(memory):
    for _ in range(2):
        seed_incident(memory, entity_id="203.0.113.9", response_status="FAILED")

    found = _patterns(memory, PatternType.REPEATED_RESPONSE_FAILURE)

    assert found and found[0].occurrences == 2


def test_benign_incidents_do_not_create_attacker_patterns(memory):
    for _ in range(5):
        seed_incident(
            memory, entity_id="203.0.113.4", predicted_label="BENIGN", status="benign"
        )

    assert not _patterns(memory, PatternType.REPEAT_ATTACKER)
    assert not _patterns(memory, PatternType.FREQUENT_THREAT)


def test_guard_friction_reports_the_overridden_engine(memory):
    for index in range(3):
        seed_incident(
            memory,
            entity_id=f"203.0.113.{index}",
            response_status="DOWNGRADED",
            decision_engine="OllamaDecisionEngine",
        )

    found = _patterns(memory, PatternType.GUARD_FRICTION)

    assert found
    assert found[0].evidence["decision_engine"] == "OllamaDecisionEngine"


def test_thresholds_are_configurable(memory):
    seed_incident(memory, entity_id="203.0.113.7")
    seed_incident(memory, entity_id="203.0.113.7")

    patterns = PatternDiscovery(
        PatternThresholds(repeat_attacker=2)
    ).discover(_incidents(memory))

    assert any(p.pattern_type is PatternType.REPEAT_ATTACKER for p in patterns)


def test_empty_history_yields_no_patterns():
    assert PatternDiscovery().discover([]) == []


def _patterns(memory: FakeMemoryProvider, pattern_type: PatternType):
    return [
        p for p in PatternDiscovery().discover(_incidents(memory))
        if p.pattern_type is pattern_type
    ]


# ── Recommendations ───────────────────────────────────────────────────────────


def _recommend(memory: FakeMemoryProvider, *, min_sample_size: int = 2):
    incidents = _incidents(memory)
    metrics   = MetricsEngine(min_sample_size=min_sample_size).compute(incidents)
    patterns  = PatternDiscovery().discover(incidents)
    labeled   = sum(1 for i in incidents if i.is_labeled)
    return RecommendationEngine().recommend(
        metrics,
        patterns,
        feedback_coverage=(labeled / len(incidents)) if incidents else 0.0,
        total_incidents=len(incidents),
    )


def test_no_history_produces_no_recommendations(memory):
    assert _recommend(memory) == []


def test_insufficient_evidence_suppresses_tuning_and_asks_for_labels(memory):
    """The honest output is "we cannot tell you yet", not a guess."""
    for index in range(5):
        seed_incident(memory, entity_id=f"203.0.113.{index}")

    types = {r.recommendation_type for r in _recommend(memory, min_sample_size=10)}

    assert RecommendationType.COLLECT_MORE_FEEDBACK in types
    assert RecommendationType.RAISE_CONFIDENCE_THRESHOLD not in types
    assert RecommendationType.LOWER_CONFIDENCE_THRESHOLD not in types
    assert RecommendationType.RETRAIN_MODEL not in types


def test_high_false_positive_rate_recommends_raising_the_threshold(memory):
    agent = LearningAgent(memory, min_sample_size=2)
    for index in range(4):
        detection_id = seed_incident(memory, entity_id=f"203.0.113.{index}", status="detected")
        verdict = AnalystVerdict.CORRECT if index == 0 else AnalystVerdict.FALSE_POSITIVE
        agent.record_feedback(detection_id=detection_id, verdict=verdict, analyst="s")

    recommendations = _recommend(memory)
    types = {r.recommendation_type for r in recommendations}

    assert RecommendationType.RAISE_CONFIDENCE_THRESHOLD in types
    # Pairs with a cheaper default while precision is low.
    assert RecommendationType.PREFER_LESS_DISRUPTIVE_ACTION in types


def test_false_negatives_outrank_false_positives(memory):
    """A missed threat produces no alert and no record — it is the worst error."""
    agent = LearningAgent(memory, min_sample_size=2)
    for index in range(3):
        detection_id = seed_incident(
            memory, entity_id=f"203.0.113.{index}",
            predicted_label="BENIGN", status="benign",
        )
        agent.record_feedback(
            detection_id=detection_id, verdict=AnalystVerdict.INCORRECT, analyst="s"
        )

    recommendations = _recommend(memory)

    assert recommendations[0].recommendation_type is RecommendationType.LOWER_CONFIDENCE_THRESHOLD
    assert recommendations[0].priority.value == "CRITICAL"


def test_failed_responses_recommend_reviewing_the_executor(memory):
    for index in range(3):
        seed_incident(memory, entity_id=f"203.0.113.{index}", response_status="FAILED")

    types = {r.recommendation_type for r in _recommend(memory)}

    assert RecommendationType.REVIEW_EXECUTOR in types


def test_recurring_incidents_recommend_a_containment_rule(memory):
    for _ in range(3):
        seed_incident(memory, entity_id="203.0.113.20")

    recommendations = [
        r for r in _recommend(memory)
        if r.recommendation_type is RecommendationType.ADD_CONTAINMENT_RULE
    ]

    assert recommendations
    assert "203.0.113.20" in recommendations[0].suggested_change


def test_every_recommendation_describes_a_human_action(memory):
    agent = LearningAgent(memory, min_sample_size=2)
    for index in range(4):
        detection_id = seed_incident(memory, entity_id=f"203.0.113.{index}", status="detected")
        agent.record_feedback(
            detection_id=detection_id, verdict=AnalystVerdict.FALSE_POSITIVE, analyst="s"
        )

    for recommendation in _recommend(memory):
        assert recommendation.suggested_change.strip()
        assert recommendation.rationale.strip()
        assert recommendation.evidence or recommendation.supporting_patterns
