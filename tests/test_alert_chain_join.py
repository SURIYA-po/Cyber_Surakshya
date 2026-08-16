"""Correlation tests for the detection -> analysis -> decision -> response chain.

The read model used to take the newest 100 detections, the newest 100 analyses
and the newest 100 decisions as three independent windows and join them in
Python. Nothing required those windows to overlap, so an alert on the first page
could have its analysis outside the newest hundred analyses and the dashboard
reported "No analysis available" for work that had been done.

These tests pin the replacement: children are resolved by domain identifier,
newest wins, and the query count is a function of pipeline depth rather than
page size.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from api import runtime as runtime_module
from api.projections import (
    build_alerts_from_memory_records,
    fetch_alert_chain,
    load_alert,
    load_alert_detail,
)
from memory.inmemory import InMemoryMemoryProvider
from memory.models import MemoryRecord

BASE = datetime(2026, 8, 1, tzinfo=timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


# ── Record factories ─────────────────────────────────────────────────────────


def detection(
    detection_id="det-1",
    *,
    event_id="evt-1",
    correlation_id=None,
    minutes=0,
    label="PortScan",
    status="detected",
    in_metadata=True,
):
    metadata = {"agent": "detection_agent", "severity_label": "LOW"}
    if in_metadata and detection_id:
        metadata["detection_id"] = detection_id
        metadata["event_id"] = event_id
    content = {
        "predicted_label": label,
        "confidence": 0.91,
        "status": status,
        "risk_score": 36.4,
        "risk_level": "LOW",
        "severity_label": "LOW",
    }
    if detection_id:
        content["detection_id"] = detection_id
    if event_id:
        content["event_id"] = event_id
    return MemoryRecord(
        collection="detections",
        record_type="detection_result",
        entity_id="10.0.0.5",
        correlation_id=correlation_id,
        content=content,
        metadata=metadata,
        created_at=BASE + timedelta(minutes=minutes),
    )


def analysis(
    analysis_id="ana-1",
    detection_id="det-1",
    *,
    event_id="evt-1",
    correlation_id=None,
    minutes=1,
    summary="Analysis summary",
    confidence=0.87,
    in_metadata=True,
):
    metadata = {"agent": "analysis_agent"}
    if in_metadata:
        metadata["detection_id"] = detection_id
        metadata["analysis_id"] = analysis_id
        metadata["event_id"] = event_id
    return MemoryRecord(
        collection="analysis",
        record_type="analysis_result",
        entity_id="10.0.0.5",
        correlation_id=correlation_id,
        content={
            "analysis_id": analysis_id,
            "detection_id": detection_id,
            "event_id": event_id,
            "summary": summary,
            "confidence": confidence,
            "reasoning": "Because of the flow shape.",
            "analysis_engine": "DeterministicRuleEngine",
        },
        metadata=metadata,
        created_at=BASE + timedelta(minutes=minutes),
    )


def decision(
    decision_id="dec-1",
    analysis_id="ana-1",
    detection_id="det-1",
    *,
    correlation_id=None,
    minutes=2,
    action="BLOCK_IP",
    priority="HIGH",
    requires_approval=False,
):
    return MemoryRecord(
        collection="decisions",
        record_type="decision_result",
        entity_id="10.0.0.5",
        correlation_id=correlation_id,
        content={
            "decision_id": decision_id,
            "analysis_id": analysis_id,
            "detection_id": detection_id,
            "action_type": action,
            "action_target_value": "10.0.0.5",
            "priority": priority,
            "requires_approval": requires_approval,
            "approval_status": "NOT_REQUIRED" if not requires_approval else "PENDING",
            "rationale": "Policy rule 1 matched.",
            "confidence": 0.95,
            "decision_engine": "DeterministicDecisionEngine",
        },
        metadata={
            "agent": "decision_agent",
            "detection_id": detection_id,
            "analysis_id": analysis_id,
            "decision_id": decision_id,
        },
        created_at=BASE + timedelta(minutes=minutes),
    )


def response(
    response_id="res-1",
    decision_id="dec-1",
    *,
    correlation_id=None,
    minutes=3,
    status="EXECUTED",
    guard_verdict="ALLOW",
    guard_reason="Deterministic engine, non-destructive action.",
    executor="firewall",
):
    return MemoryRecord(
        collection="responses",
        record_type="response_result",
        entity_id="10.0.0.5",
        correlation_id=correlation_id,
        content={
            "response_id": response_id,
            "decision_id": decision_id,
            "status": status,
            "action_type": "BLOCK_IP",
            "guard_verdict": guard_verdict,
            "guard_reason": guard_reason,
            "executor_name": executor,
            "executed_at": (BASE + timedelta(minutes=minutes)).isoformat(),
        },
        metadata={"agent": "response_agent", "decision_id": decision_id},
        created_at=BASE + timedelta(minutes=minutes),
    )


# ── Provider fixtures ────────────────────────────────────────────────────────


class CountingProvider:
    """Wraps a provider and counts `search` calls, to prove there is no N+1."""

    def __init__(self, inner):
        self._inner = inner
        self.searches: list[str] = []

    def search(self, collection, query):
        self.searches.append(collection)
        return self._inner.search(collection, query)

    def __getattr__(self, name):
        return getattr(self._inner, name)


@pytest.fixture
def memory(monkeypatch):
    provider = CountingProvider(InMemoryMemoryProvider())
    # A non-None runtime short-circuits ensure_runtime(), so these tests never
    # build the ML pipeline.
    monkeypatch.setattr(runtime_module.platform, "runtime", object())
    monkeypatch.setattr(runtime_module.platform, "memory_provider", provider)
    return provider


def seed(provider, *records):
    for record in records:
        provider.store(record.collection, record)


# ── Resolution ───────────────────────────────────────────────────────────────


def test_detection_with_analysis():
    alert = build_alerts_from_memory_records([detection()], [analysis()])[0]
    assert alert["analysis"]["id"] == "ana-1"
    assert alert["threat_assessment"]["analysis_confidence"] == 0.87


def test_detection_without_analysis():
    alert = build_alerts_from_memory_records([detection()], [])[0]
    assert "analysis" not in alert
    assert alert["threat_assessment"]["analysis_confidence"] is None
    # Absent, not zero: "not analysed" and "analysed with no confidence" differ.
    assert alert["threat_assessment"]["detection_confidence"] == 0.91


def test_multiple_analyses_newest_wins():
    """Re-analysing a detection must surface the new assessment.

    The old index was a dict assignment in a loop over newest-first records, so
    the last write — the oldest record — won.
    """
    older = analysis("ana-old", minutes=1, summary="Older", confidence=0.10)
    newer = analysis("ana-new", minutes=9, summary="Newer", confidence=0.90)

    for ordering in ([older, newer], [newer, older]):
        alert = build_alerts_from_memory_records([detection()], ordering)[0]
        assert alert["analysis"]["id"] == "ana-new"
        assert alert["analysis"]["summary"] == "Newer"


def test_analysis_for_another_detection_does_not_leak():
    foreign = analysis("ana-2", detection_id="det-2", event_id="evt-2")
    alert = build_alerts_from_memory_records([detection("det-1")], [foreign])[0]
    assert "analysis" not in alert


def test_ambiguous_correlation_fallback_is_dropped_not_guessed():
    """A run-scoped key cannot tell one detection's analysis from another's."""
    shared = _uuid()
    det = detection("det-1", correlation_id=shared, in_metadata=False)
    # Neither analysis carries a join key in metadata or content, so only the
    # run-scoped correlation_id is left — and two records claim it.
    a1 = analysis("ana-1", detection_id="", correlation_id=shared, in_metadata=False)
    a2 = analysis("ana-2", detection_id="", correlation_id=shared, in_metadata=False)
    a1.content.pop("detection_id")
    a1.content.pop("event_id")
    a2.content.pop("detection_id")
    a2.content.pop("event_id")

    alert = build_alerts_from_memory_records([det], [a1, a2])[0]
    assert "analysis" not in alert


def test_detection_analysis_decision():
    alert = build_alerts_from_memory_records(
        [detection()], [analysis()], [decision()]
    )[0]
    assert alert["response_action"]["decision_id"] == "dec-1"
    assessment = alert["threat_assessment"]["decision"]
    assert assessment["action"] == "BLOCK_IP"
    assert assessment["priority"] == "HIGH"
    assert assessment["rationale"] == "Policy rule 1 matched."


def test_missing_detection_id_is_unjoinable_not_invented():
    """record_id must never stand in for a missing domain id."""
    orphan = detection(detection_id=None, event_id=None, in_metadata=False)
    alert = build_alerts_from_memory_records([orphan], [analysis()])[0]

    assert alert["detection_id"] is None
    assert alert["joinable"] is False
    assert "analysis" not in alert
    # Still addressable and deletable by its storage key.
    assert alert["id"] == orphan.record_id
    assert alert["record_id"] == orphan.record_id


def test_joinable_is_true_for_a_well_formed_detection():
    alert = build_alerts_from_memory_records([detection()])[0]
    assert alert["joinable"] is True


# ── Response outcome ─────────────────────────────────────────────────────────


def _assessment_decision(resp):
    alerts = build_alerts_from_memory_records(
        [detection()], [analysis()], [decision()], [resp] if resp else []
    )
    return alerts[0]["threat_assessment"]["decision"]


def test_decision_without_response():
    view = _assessment_decision(None)
    assert view["action"] == "BLOCK_IP"
    # Never claimed as done. "Not yet acted on" is not "acted on".
    assert view["response_status"] is None
    assert view["executed"] is None
    assert view["guard_intervened"] is None


def test_executed_response():
    view = _assessment_decision(response(status="EXECUTED"))
    assert view["response_status"] == "EXECUTED"
    assert view["executed"] is True
    assert view["guard_intervened"] is False
    assert view["executor"] == "firewall"


def test_awaiting_approval_response():
    view = _assessment_decision(
        response(
            status="AWAITING_APPROVAL",
            guard_verdict="REQUIRE_APPROVAL",
            guard_reason="Destructive action requires an analyst.",
            executor=None,
        )
    )
    assert view["response_status"] == "AWAITING_APPROVAL"
    assert view["executed"] is False
    assert view["guard_intervened"] is True
    assert view["guard_reason"] == "Destructive action requires an analyst."


def test_guard_refused_response():
    view = _assessment_decision(
        response(
            status="BLOCKED_BY_GUARD",
            guard_verdict="DENY",
            guard_reason="Target is a protected asset.",
            executor=None,
        )
    )
    assert view["response_status"] == "BLOCKED_BY_GUARD"
    assert view["executed"] is False
    assert view["guard_intervened"] is True


@pytest.mark.parametrize(
    "status,executed",
    [
        ("EXECUTED", True),
        ("DOWNGRADED", True),   # a substitute action did run
        ("DRY_RUN", False),     # simulated only
        ("AWAITING_APPROVAL", False),
        ("BLOCKED_BY_GUARD", False),
        ("FAILED", False),
        ("REVERTED", False),    # rolled back; no longer in force
        ("DEDUPLICATED", False),
        ("NO_OP", False),
    ],
)
def test_executed_flag_covers_every_response_status(status, executed):
    view = _assessment_decision(response(status=status, guard_verdict="ALLOW"))
    assert view["response_status"] == status
    assert view["executed"] is executed


def test_newest_response_wins_when_a_decision_is_reverted():
    executed = response("res-1", minutes=3, status="EXECUTED")
    reverted = response("res-2", minutes=8, status="REVERTED")
    view = build_alerts_from_memory_records(
        [detection()], [analysis()], [decision()], [executed, reverted]
    )[0]["threat_assessment"]["decision"]

    assert view["response_status"] == "REVERTED"
    assert view["executed"] is False


# ── Loading: the list path ───────────────────────────────────────────────────


def test_list_path_with_multiple_alerts(memory):
    for n in range(1, 4):
        seed(
            memory,
            detection(f"det-{n}", event_id=f"evt-{n}", minutes=n),
            analysis(f"ana-{n}", f"det-{n}", event_id=f"evt-{n}", minutes=n),
            decision(f"dec-{n}", f"ana-{n}", f"det-{n}", minutes=n),
            response(f"res-{n}", f"dec-{n}", minutes=n),
        )

    detections, analyses, decisions, responses = fetch_alert_chain()
    alerts = build_alerts_from_memory_records(
        detections, analyses, decisions, responses
    )

    assert len(alerts) == 3
    for alert in alerts:
        n = alert["detection_id"].split("-")[1]
        assert alert["analysis"]["id"] == f"ana-{n}"
        assert alert["response_action"]["decision_id"] == f"dec-{n}"
        assert alert["threat_assessment"]["decision"]["executed"] is True


def test_analysis_outside_the_newest_hundred_is_still_joined(memory):
    """The screenshot bug, at the list level.

    Three detections whose analyses are the *oldest* records in a large analysis
    collection. Under three independent newest-100 windows these were invisible.
    """
    for n in range(1, 4):
        seed(
            memory,
            detection(f"det-{n}", event_id=f"evt-{n}", minutes=n),
            analysis(f"ana-{n}", f"det-{n}", event_id=f"evt-{n}", minutes=n),
        )
    # 200 newer analyses belonging to detections that are not on this page.
    for n in range(200):
        seed(
            memory,
            analysis(
                f"noise-ana-{n}",
                f"noise-det-{n}",
                event_id=f"noise-evt-{n}",
                minutes=1000 + n,
            ),
        )

    detections, analyses, decisions, responses = fetch_alert_chain()
    alerts = build_alerts_from_memory_records(
        detections, analyses, decisions, responses
    )

    assert len(alerts) == 3
    assert all("analysis" in alert for alert in alerts)


def test_list_path_issues_no_n_plus_one_queries(memory):
    """Query count must depend on pipeline depth, not on how many alerts."""

    def build(count):
        memory.searches.clear()
        for n in range(count):
            seed(
                memory,
                detection(f"d{count}-{n}", event_id=f"e{count}-{n}", minutes=n),
                analysis(f"a{count}-{n}", f"d{count}-{n}", event_id=f"e{count}-{n}", minutes=n),
                decision(f"c{count}-{n}", f"a{count}-{n}", f"d{count}-{n}", minutes=n),
                response(f"r{count}-{n}", f"c{count}-{n}", minutes=n),
            )
        memory.searches.clear()
        fetch_alert_chain()
        return list(memory.searches)

    few = build(3)
    many = build(30)

    # One query per collection in the chain, either way.
    assert few == ["detections", "analysis", "decisions", "responses"]
    assert many == few


# ── Loading: the detail path ─────────────────────────────────────────────────


def test_detail_path_reads_only_one_chain(memory):
    for n in range(1, 21):
        seed(
            memory,
            detection(f"det-{n}", event_id=f"evt-{n}", minutes=n),
            analysis(f"ana-{n}", f"det-{n}", event_id=f"evt-{n}", minutes=n),
            decision(f"dec-{n}", f"ana-{n}", f"det-{n}", minutes=n),
            response(f"res-{n}", f"dec-{n}", minutes=n),
        )

    memory.searches.clear()
    alert = load_alert("det-7")

    assert alert["detection_id"] == "det-7"
    assert alert["analysis"]["id"] == "ana-7"
    assert alert["response_action"]["decision_id"] == "dec-7"
    # One query per hop, and nothing that scales with the collection.
    assert memory.searches == ["detections", "analysis", "decisions", "responses"]


def test_detail_payload_carries_the_chain(memory):
    seed(
        memory,
        detection("det-1", minutes=1),
        analysis("ana-1", "det-1", minutes=1),
        decision("dec-1", "ana-1", "det-1", minutes=1),
        response("res-1", "dec-1", minutes=1, status="EXECUTED"),
    )

    payload = load_alert_detail("det-1")

    assert payload["analysis_summary"] == "Analysis summary"
    assert payload["confidence_score"] == 87.0
    assert payload["threat_assessment"]["decision"]["executed"] is True
    assert [entry["title"] for entry in payload["timeline"]] == [
        "Detection recorded",
        "Analysis completed",
        "Decision executed",
    ]


def test_detail_path_finds_an_old_detection_whose_analysis_is_buried(memory):
    """The exact failure in the screenshot, at the detail level."""
    seed(
        memory,
        detection("det-old", event_id="evt-old", minutes=0),
        analysis("ana-old", "det-old", event_id="evt-old", minutes=1),
    )
    for n in range(300):
        seed(
            memory,
            analysis(
                f"noise-{n}", f"noise-det-{n}", event_id=f"noise-evt-{n}", minutes=500 + n
            ),
        )

    alert = load_alert("det-old")
    assert alert["analysis"]["id"] == "ana-old"


def test_detail_path_returns_none_for_an_unknown_alert(memory):
    seed(memory, detection("det-1"))
    assert load_alert("det-does-not-exist") is None
    assert load_alert_detail("det-does-not-exist") is None


def test_detail_path_finds_a_legacy_detection_without_metadata_ids(memory):
    """Records written before the join keys were persisted in metadata."""
    seed(
        memory,
        detection("det-legacy", event_id="evt-legacy", minutes=1, in_metadata=False),
        analysis("ana-legacy", "det-legacy", event_id="evt-legacy", minutes=2,
                 in_metadata=False),
    )

    alert = load_alert("det-legacy")
    assert alert is not None
    assert alert["detection_id"] == "det-legacy"
