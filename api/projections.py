"""Read-model projections: stored records -> dashboard shapes.

The API layer never returns a domain object directly. These functions turn the
MemoryRecords written by the agents into the flat dictionaries the frontend
consumes, keeping schema changes in one place instead of spread across every
endpoint.

Shared by the alerts, status, response, and simulation routers.
"""
from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any

from agents.response.response_agent import RESPONSE_COLLECTION
from api.runtime import ensure_runtime, platform
from cyber_surakshya.platform.enums.detection_status import DetectionStatus
from cyber_surakshya.platform.enums.risk_level import RiskLevel
from cyber_surakshya.platform.enums.severity import Severity
from cyber_surakshya.platform.risk.score import RISK_BANDS, risk_level_from_score
from cyber_surakshya.platform.actions.action import Action
from cyber_surakshya.platform.actions.action_parameters import ActionParameters
from cyber_surakshya.platform.actions.action_target import ActionTarget
from cyber_surakshya.platform.actions.action_type import ActionType
from cyber_surakshya.platform.audit.metadata import AuditMetadata
from cyber_surakshya.platform.schemas.response_result import (
    EngineTrustTier,
    GuardVerdict,
    ResponseResult,
    ResponseStatus,
)
from memory.models import MemoryQuery, MemoryRecord


def iso_utc(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# Dashboard labels for the persisted DetectionStatus. Workflow status used to
# be re-derived from the predicted label alone — anything outside a benign word
# list became "Investigating", everything else "Resolved" — which collapsed
# INCONCLUSIVE onto "Resolved". INCONCLUSIVE is precisely the verdict "the
# supervised layer said benign but the anomaly layer disagreed", so the flow
# most in need of an analyst was the one labelled as needing nothing.
DETECTION_STATUS_LABELS: dict[str, str] = {
    DetectionStatus.DETECTED.value:     "Investigating",
    DetectionStatus.BENIGN.value:       "Resolved",
    DetectionStatus.INCONCLUSIVE.value: "Needs Review",
    DetectionStatus.ERROR.value:        "Error",
}

# Only consulted for records written before DetectionStatus was persisted, or
# by a producer using its own status vocabulary.
BENIGN_LABELS: frozenset[str] = frozenset({"BENIGN", "NORMAL", "SAFE", "NONE"})


def normalize_severity(value: Any) -> str:
    """Render a stored severity as its platform label.

    Producers disagree on the wire format. DetectionAgent persists
    ``Severity.value`` — the IntEnum ordinal, so MEDIUM arrives as ``3`` — while
    the simulation router persists ``Severity.name``. Both feed this one
    consumer, so real alerts rendered their severity as the bare string "3".
    Ordinals are mapped back to their label here; anything already textual
    passes through upper-cased, and nothing is invented for an unrecognized
    value.
    """
    if value is None:
        return "MEDIUM"
    try:
        return Severity(int(value)).name
    except (TypeError, ValueError):
        return str(value).upper()


def alert_status(stored_status: Any, predicted_label: Any) -> str:
    """Map the persisted DetectionStatus to its dashboard label."""
    if stored_status is not None:
        label = DETECTION_STATUS_LABELS.get(str(stored_status).strip().lower())
        if label is not None:
            return label
    is_attack = str(predicted_label).upper() not in BENIGN_LABELS
    return "Investigating" if is_attack else "Resolved"


def _optional_float(value: Any) -> float | None:
    """Coerce to float, or None. Never substitutes a stand-in number."""
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _as_fraction(value: Any) -> float | None:
    """Confidence as a 0–1 fraction, whatever scale it was stored on.

    The scale conversion happens here and nowhere else. Previously the API
    emitted analysis confidence as a 0–1 fraction and detection confidence as a
    percentage under a similar name, and the frontend applied a single
    ``%`` suffix to whichever it received — so a 0.87 analysis confidence
    displayed as "0.9%".
    """
    number = _optional_float(value)
    if number is None:
        return None
    if number > 1.0:
        number = number / 100.0
    return round(min(max(number, 0.0), 1.0), 6)


def _risk_band(level: str | None) -> list[float] | None:
    """Inclusive [lower, upper] bounds of a named risk band."""
    if not level or level not in RiskLevel.__members__:
        return None
    lower, upper = RISK_BANDS[RiskLevel[level]]
    return [lower, upper]


def build_threat_assessment(
    content: dict[str, Any] | None,
    metadata: dict[str, Any] | None = None,
    analysis: dict[str, Any] | None = None,
    decision: dict[str, Any] | None = None,
    response: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Project the stored pipeline verdict into the Threat Assessment read model.

    This is the single place where a threat assessment is assembled. Every field
    is read back from what Detection, Analysis, and Decision actually computed
    and persisted; nothing here calculates security intelligence, and nothing is
    defaulted to a plausible-looking constant. An absent score is ``None``, and
    the client is expected to say so rather than draw a bar.

    The card this feeds previously had no calculation behind it at all. Its
    score was the alert's ``confidence_score``, which was the literal ``95``
    whenever no analysis record existed — rendered as "95.0/100" under a red
    CRITICAL bar, on benign traffic. The IDSDetectionAdapter's real score
    (consequence x certainty, see ``_risk_score_for``) had been persisted on the
    detection record the entire time and was simply never read.

    ``band`` travels with ``level`` so the client can style by band membership
    instead of re-declaring thresholds in view code and drifting out of step
    with ``RISK_BANDS``.
    """
    content  = content or {}
    metadata = metadata or {}

    score = _optional_float(content.get("risk_score"))
    level = content.get("risk_level")
    if not level and score is not None:
        # Records predating risk_level being persisted. The band is a pure
        # function of the score, so it is recovered rather than dropped.
        level = risk_level_from_score(score).name
    level = str(level).upper() if level else None

    severity_raw = (
        content.get("severity_label")
        or metadata.get("severity_label")
        or metadata.get("severity")
        or content.get("severity")
    )
    detection_status = content.get("status")
    is_anomaly = content.get("is_anomaly")

    return {
        # 0–100, or None when the detection predates the risk model.
        "score": score,
        "level": level,
        "band": _risk_band(level),
        "rationale": content.get("risk_rationale"),
        "severity": normalize_severity(severity_raw) if severity_raw is not None else None,
        # The raw DetectionStatus, distinct from the workflow status on the
        # alert card: "INCONCLUSIVE" is not "Needs Review", it is why.
        "detection_status": str(detection_status).upper() if detection_status else None,
        # Two different quantities, deliberately not merged: how sure the
        # classifier was of its label, and how sure the AnalysisAgent was of its
        # assessment. Both are fractions in [0, 1]; the client formats them.
        "detection_confidence": _as_fraction(content.get("confidence")),
        "analysis_confidence": (
            _as_fraction(analysis.get("confidence")) if analysis else None
        ),
        "is_anomaly": bool(is_anomaly) if is_anomaly is not None else None,
        # No MITRE mapping exists in the platform yet. The frontend hardcoded
        # "T1190" for every alert, benign ones included. None is the honest
        # answer until a real label -> technique mapping is built.
        "mitre": None,
        # What the pipeline decided to do about it *and* what became of that
        # decision, so the assessment covers the whole chain rather than
        # stopping at the score — and never implies an action was carried out
        # when the ResponseAgent did not carry it out.
        "decision": _decision_view(decision, response),
        # Which engine produced each component. Once Zeek/Suricata/host
        # adapters and LLM-backed engines write into the same collections, an
        # assessment stays attributable to the thing that made it.
        "provenance": {
            "detection_source": content.get("detection_source"),
            "detection_model": content.get("model_name"),
            "analysis_engine": analysis.get("engine") if analysis else None,
            "decision_engine": (decision or {}).get("decision_engine"),
        },
    }


# The only statuses in which a side-effect actually reached the outside world.
# DRY_RUN simulated it, DEDUPLICATED deferred to an earlier response, REVERTED
# rolled one back, and the rest never reached an executor. A recommendation must
# never be reported as carried out on the strength of having been recommended.
EXECUTED_RESPONSE_STATUSES: frozenset[str] = frozenset(
    {ResponseStatus.EXECUTED.value, ResponseStatus.DOWNGRADED.value}
)


def _response_outcome(response: dict[str, Any] | None) -> dict[str, Any]:
    """What the ResponseAgent actually did about a decision.

    All-None when no response record exists: "not yet acted on" and "acted on
    and failed" are different states and must not collapse into each other.
    """
    if not response:
        return {
            "response_status": None,
            "executed": None,
            "guard_intervened": None,
            "guard_verdict": None,
            "guard_reason": None,
            "executor": None,
            "external_reference": None,
            "responded_at": None,
        }

    status  = response.get("status")
    verdict = response.get("guard_verdict")
    return {
        "response_status": status,
        "executed": str(status) in EXECUTED_RESPONSE_STATUSES if status else None,
        # ALLOW is the guard standing aside. Every other verdict — DENY,
        # DOWNGRADE, REQUIRE_APPROVAL, ALLOW_DRY_RUN — changed the outcome.
        "guard_intervened": (
            verdict != GuardVerdict.ALLOW.value if verdict else None
        ),
        "guard_verdict": verdict,
        "guard_reason": response.get("guard_reason"),
        "executor": response.get("executor_name"),
        "external_reference": response.get("external_reference"),
        "responded_at": response.get("executed_at"),
    }


def _decision_view(
    decision: dict[str, Any] | None,
    response: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """The DecisionAgent's recommendation, plus what became of it."""
    if not decision:
        return None
    return {
        "action": decision.get("action_type"),
        "target": decision.get("action_target_value"),
        "priority": decision.get("priority"),
        "requires_approval": bool(decision.get("requires_approval")),
        "approval_status": decision.get("approval_status"),
        "rationale": decision.get("rationale"),
        "confidence": _as_fraction(decision.get("confidence")),
        **_response_outcome(response),
    }


# ── Record correlation ────────────────────────────────────────────────────────
#
# The pipeline is a chain of one-to-many edges:
#
#   Detection --detection_id--> Analysis --analysis_id--> Decision
#                                            --decision_id--> Response
#
# Children are resolved by their domain identifier only. MemoryRecord.record_id
# is the storage primary key and a different value entirely, so substituting it
# for a missing domain id yields an alert whose id matches nothing downstream —
# the join silently resolves to nothing and the UI reports "no analysis".

#: Keys scoped to a pipeline *run* rather than to one parent. Every record in a
#: multi-event run shares them, so they can only disambiguate when the run
#: produced exactly one child; otherwise the link is dropped rather than
#: guessed at.
RUN_SCOPED_KEYS: frozenset[str] = frozenset({"correlation_id", "trace_id"})


def reference_id(record: MemoryRecord, key: str) -> str | None:
    """Read a domain identifier off a record: metadata, then content, then field.

    Metadata first because that is what the providers can filter on, so a key
    present there is also a key the join can query by.
    """
    metadata = record.metadata or {}
    value = metadata.get(key)
    if value:
        return str(value)
    content = record.content if isinstance(record.content, dict) else {}
    value = content.get(key)
    if value:
        return str(value)
    value = getattr(record, key, None)
    return str(value) if value else None


class ChildIndex:
    """Newest child record per parent, resolvable by a chain of fallback keys.

    Two rules, both of which the previous lookup got wrong:

    *Newest wins.* Iteration order is never trusted. The old index was a plain
    dict assignment inside a loop over records ordered newest-first, so the
    final write — the *oldest* record — won. Re-analysing a detection surfaced
    the superseded assessment.

    *Run-scoped keys must be unambiguous.* correlation_id is shared by every
    record in a run, so in a multi-event run it cannot tell one detection's
    analysis from another's. When one is claimed by more than one parent it is
    dropped rather than resolved to whichever record sorted highest.
    """

    __slots__ = ("_keys", "_tables", "_claimants")

    def __init__(self, *keys: str) -> None:
        """Args: keys, most specific edge first."""
        self._keys = keys
        self._tables: dict[str, dict[str, MemoryRecord]] = {k: {} for k in keys}
        self._claimants: dict[str, dict[str, set[str]]] = {k: {} for k in keys}

    def add(self, record: MemoryRecord) -> None:
        identity = reference_id(record, self._keys[0]) or record.record_id
        for key in self._keys:
            value = reference_id(record, key)
            if not value:
                continue
            self._claimants[key].setdefault(value, set()).add(identity)
            existing = self._tables[key].get(value)
            if existing is None or record.created_at > existing.created_at:
                self._tables[key][value] = record

    def resolve(self, **ids: str | None) -> MemoryRecord | None:
        """Return the child for a parent, trying each key in declared order."""
        for key in self._keys:
            value = ids.get(key)
            if not value:
                continue
            value = str(value)
            if key in RUN_SCOPED_KEYS and len(self._claimants[key].get(value, ())) > 1:
                continue
            hit = self._tables[key].get(value)
            if hit is not None:
                return hit
        return None


def build_child_index(
    records: list[MemoryRecord] | None,
    *keys: str,
) -> ChildIndex:
    index = ChildIndex(*keys)
    for record in records or []:
        index.add(record)
    return index


def analysis_lookup_view(record: MemoryRecord) -> dict[str, Any]:
    """Project one resolved analysis record into the alert's `analysis` block."""
    content = record.content if isinstance(record.content, dict) else {}
    return {
        "id": content.get("analysis_id") or record.record_id,
        "alert_id": reference_id(record, "detection_id"),
        "prediction": content.get("summary") or "Unknown",
        "confidence": content.get("confidence") or 0,
        "summary": content.get("summary") or "Analysis generated from persisted memory.",
        # The AnalysisAgent's own assessment, now that it is persisted. These
        # carry the "AI Threat Analysis" panel, which had been rendering a
        # hardcoded recommendation list because the API exposed nothing else.
        "reasoning": content.get("reasoning"),
        "evidence": content.get("evidence") or [],
        "uncertainty": content.get("uncertainty") or [],
        "risk_score": content.get("risk_score"),
        "risk_level": content.get("risk_level"),
        "severity": content.get("severity_label"),
        "engine": content.get("analysis_engine"),
        "created_at": iso_utc(record.created_at),
    }


def decision_lookup_view(record: MemoryRecord) -> dict[str, Any]:
    """Project one resolved decision record into the alert's `response_action`."""
    content = record.content if isinstance(record.content, dict) else {}
    return {
        "action_type": content.get("action_type") or "observe",
        "action_target_type": content.get("action_target_type"),
        "action_target_value": content.get("action_target_value"),
        "requires_approval": content.get("requires_approval") is True,
        "approval_status": content.get("approval_status"),
        "priority": content.get("priority") or "MEDIUM",
        "rationale": content.get("rationale"),
        "confidence": content.get("confidence"),
        "decision_engine": content.get("decision_engine"),
        "decision_id": content.get("decision_id"),
        "memory_hits": content.get("memory_hits") or 0,
        "created_at": iso_utc(record.created_at),
    }


def build_alerts_from_memory_records(
    detection_records: list[MemoryRecord],
    analysis_records: list[MemoryRecord] | None = None,
    decision_records: list[MemoryRecord] | None = None,
    response_records: list[MemoryRecord] | None = None,
) -> list[dict[str, Any]]:
    """Project detections and their downstream chain into dashboard alerts.

    Detections drive: each one resolves its own analysis, that analysis its
    decision, and that decision its response. Children are indexed once and
    resolved in memory, so the projection issues no queries of its own and the
    caller's query count does not grow with the number of alerts.
    """
    analyses  = build_child_index(
        analysis_records, "detection_id", "event_id", "correlation_id"
    )
    decisions = build_child_index(
        decision_records, "analysis_id", "detection_id", "event_id", "correlation_id"
    )
    responses = build_child_index(response_records, "decision_id", "correlation_id")

    alerts: list[dict[str, Any]] = []
    for record in detection_records:
        content = record.content if isinstance(record.content, dict) else {}
        metadata = record.metadata or {}

        # No record_id substitute. A detection with no detection_id cannot be
        # joined to anything, and inventing an id for it would produce an alert
        # that silently resolves to no analysis and no decision.
        detection_id = reference_id(record, "detection_id")
        event_id = reference_id(record, "event_id")
        predicted_label = (
            content.get("predicted_label") or content.get("prediction") or "Unknown"
        )
        severity = normalize_severity(
            content.get("severity_label")
            or metadata.get("severity_label")
            or metadata.get("severity")
            or content.get("severity")
        )

        analysis_record = decision_record = response_record = None
        if detection_id:
            analysis_record = analyses.resolve(
                detection_id=detection_id,
                event_id=event_id,
                correlation_id=record.correlation_id,
            )
            decision_record = decisions.resolve(
                analysis_id=(
                    reference_id(analysis_record, "analysis_id")
                    if analysis_record
                    else None
                ),
                detection_id=detection_id,
                event_id=event_id,
                correlation_id=record.correlation_id,
            )
            if decision_record is not None:
                response_record = responses.resolve(
                    decision_id=reference_id(decision_record, "decision_id"),
                    correlation_id=decision_record.correlation_id,
                )

        analysis = analysis_lookup_view(analysis_record) if analysis_record else None
        decision = decision_lookup_view(decision_record) if decision_record else None
        response = (
            response_record.content
            if response_record is not None and isinstance(response_record.content, dict)
            else None
        )

        alert = {
            # The addressable identity of this alert. Falls back to the memory
            # primary key only so a malformed record stays reachable and
            # deletable — never as a stand-in domain id for joining.
            "id": detection_id or record.record_id,
            "attack_type": str(predicted_label),
            "source_ip": record.entity_id or "unknown",
            "severity": severity,
            # Read from the persisted DetectionStatus rather than guessed from
            # the label, so an INCONCLUSIVE anomaly stops reporting itself as
            # "Resolved".
            "status": alert_status(content.get("status"), predicted_label),
            "created_at": iso_utc(record.created_at),
            "detection_id": detection_id,
            "event_id": event_id,
            "correlation_id": record.correlation_id,
            "trace_id": record.trace_id,
            # False when the record carries no detection_id: nothing downstream
            # can be attributed to it, and the UI should say so rather than
            # present an alert that merely appears to have no analysis.
            "joinable": detection_id is not None,
            # The memory primary key, which differs from `id` (the detection_id
            # carried inside the record content). DELETE /alerts needs this to
            # address the stored record.
            "record_id": record.record_id,
            # The canonical assessment, attached at projection time so /alerts
            # and /alerts/{id}/detail cannot disagree about the same alert.
            "threat_assessment": build_threat_assessment(
                content, metadata, analysis, decision, response
            ),
        }

        if analysis:
            alert["analysis"] = analysis

        if decision:
            alert["response_action"] = decision

        alerts.append(alert)

    alerts.sort(key=lambda item: item.get("created_at") or "", reverse=True)
    return alerts


def build_alert_detail_payload(alert: dict[str, Any], analysis: dict[str, Any] | None = None, decision: dict[str, Any] | None = None) -> dict[str, Any]:
    timeline = [
        {
            "title": "Detection recorded",
            "time": alert.get("created_at"),
            "detail": f"{alert.get('attack_type')} detected from {alert.get('source_ip')}",
        }
    ]

    if analysis:
        timeline.append(
            {
                "title": "Analysis completed",
                "time": analysis.get("created_at"),
                "detail": analysis.get("summary"),
            }
        )

    if decision:
        timeline.append(
            {
                "title": "Decision executed",
                "time": alert.get("created_at"),
                "detail": f"Action {decision.get('action_type')} with priority {decision.get('priority')}",
            }
        )

    # The alert already carries the canonical assessment; the detail payload
    # never rebuilds it, so the two endpoints cannot drift.
    assessment = alert.get("threat_assessment") or build_threat_assessment(
        {}, None, analysis, decision
    )
    confidence = assessment.get("analysis_confidence")
    if confidence is None:
        confidence = assessment.get("detection_confidence")

    return {
        **alert,
        "threat_assessment": assessment,
        # None, not prose. This read "Auto-analyzed by deterministic rule engine
        # & dual-layer IDS." whenever no analysis record existed — an assertion
        # about work that had not happened.
        "analysis_summary": analysis.get("summary") if analysis else None,
        # Retained for the current frontend contract, which reads a percentage.
        # None when nothing was measured; it used to fall back to the literal
        # 95, which the Threat Assessment card then rendered as a 95/100
        # CRITICAL threat score.
        "confidence_score": (
            round(confidence * 100, 2) if confidence is not None else None
        ),
        "timeline": timeline,
    }


def analysis_view(record: MemoryRecord) -> dict[str, Any] | None:
    """Project one stored analysis record into the shape the dashboard reads.

    Returns None when the record carries no analysis_id, which is the caller's
    signal to skip it.
    """
    content = record.content
    if not isinstance(content, dict):
        return None

    analysis_id = content.get("analysis_id")
    if analysis_id is None:
        return None

    detection_id = content.get("detection_id")
    summary = content.get("summary")
    return {
        "id":          analysis_id,
        "alert_id":    str(detection_id) if detection_id else None,
        # `prediction` intentionally mirrors `summary`: the stored analysis
        # record has no separate predicted label. Kept for the frontend's
        # existing field contract.
        "prediction":  summary,
        "confidence":  content.get("confidence"),
        "summary":     summary,
        # Now persisted by AnalysisAgent, so the analysis views stop being a
        # summary string and a number.
        "reasoning":   content.get("reasoning"),
        "evidence":    content.get("evidence") or [],
        "uncertainty": content.get("uncertainty") or [],
        "risk_score":  content.get("risk_score"),
        "risk_level":  content.get("risk_level"),
        "severity":    content.get("severity_label"),
        "engine":      content.get("analysis_engine"),
    }


#: Ceiling on one page of alerts.
ALERT_PAGE_LIMIT = 100

#: Ceiling on the supplementary child sweep. Records written before the join
#: keys were persisted in metadata carry their parent id only inside `content`,
#: which no provider can filter on, so they are reachable only by a scan
#: bounded to the page's own time window.
CHILD_SWEEP_MULTIPLIER = 5


def _search(collection: str, query: MemoryQuery) -> list[MemoryRecord]:
    return [
        hit.record for hit in platform.memory_provider.search(collection, query)
    ]


def fetch_children(
    collection: str,
    join_key: str,
    parent_ids: list[str],
    *,
    since: datetime | None = None,
    limit: int = ALERT_PAGE_LIMIT,
) -> list[MemoryRecord]:
    """Fetch the child records belonging to a page of parents.

    At most two queries, however many parents there are — the query count is a
    function of the pipeline's depth, not of the page size. This replaces three
    independently-windowed "newest 100" reads whose windows were not required
    to overlap: an alert on page one could have its analysis outside the newest
    hundred analyses, and the dashboard then reported "no analysis available"
    for work that had in fact been done.

    1. an exact ``metadata_any`` match on the join key;
    2. only when some parents are still unmatched, one sweep bounded to the
       page's time window, which also reaches records written before the join
       key was persisted in metadata.
    """
    if not parent_ids:
        return []

    records = _search(
        collection,
        MemoryQuery(
            metadata_any={join_key: list(dict.fromkeys(parent_ids))},
            order_by="created_at",
            descending=True,
            limit=limit,
        ),
    )

    matched = {reference_id(record, join_key) for record in records}
    if all(parent_id in matched for parent_id in parent_ids):
        return records

    sweep = _search(
        collection,
        MemoryQuery(
            created_after=since,
            order_by="created_at",
            descending=True,
            limit=limit * CHILD_SWEEP_MULTIPLIER,
        ),
    )
    seen = {record.record_id for record in records}
    records.extend(record for record in sweep if record.record_id not in seen)
    return records


def fetch_alert_chain(
    limit: int = ALERT_PAGE_LIMIT,
) -> tuple[
    list[MemoryRecord], list[MemoryRecord], list[MemoryRecord], list[MemoryRecord]
]:
    """Read one page of detections and the chain hanging off it.

    Detections are the driving collection: each subsequent fetch is scoped to
    the ids the previous one produced, so nothing is read that no alert on the
    page could reference.
    """
    detections = _search(
        "detections",
        MemoryQuery(limit=limit, order_by="created_at", descending=True),
    )
    if not detections:
        return [], [], [], []

    since = min(record.created_at for record in detections)
    detection_ids = [
        value
        for value in (reference_id(record, "detection_id") for record in detections)
        if value
    ]

    analyses = fetch_children(
        "analysis", "detection_id", detection_ids, since=since, limit=limit
    )
    analysis_ids = [
        value
        for value in (reference_id(record, "analysis_id") for record in analyses)
        if value
    ]

    decisions = fetch_children(
        "decisions", "analysis_id", analysis_ids, since=since, limit=limit
    )
    decision_ids = [
        value
        for value in (reference_id(record, "decision_id") for record in decisions)
        if value
    ]

    responses = fetch_children(
        RESPONSE_COLLECTION, "decision_id", decision_ids, since=since, limit=limit
    )
    return detections, analyses, decisions, responses


def find_detection_record(alert_id: str) -> MemoryRecord | None:
    """Locate one detection by its detection_id, without reading the page."""
    hits = _search(
        "detections",
        MemoryQuery(
            metadata={"detection_id": alert_id},
            order_by="created_at",
            descending=True,
            limit=1,
        ),
    )
    if hits:
        return hits[0]

    # A malformed detection is addressed by its memory primary key, which is
    # what `id` falls back to in the projection.
    record = platform.memory_provider.get("detections", alert_id)
    if record is not None:
        return record

    # Records written before detection_id was persisted in metadata carry it
    # only in `content`, which no provider can filter on.
    for candidate in _search(
        "detections",
        MemoryQuery(
            order_by="created_at",
            descending=True,
            limit=ALERT_PAGE_LIMIT * CHILD_SWEEP_MULTIPLIER,
        ),
    ):
        if reference_id(candidate, "detection_id") == alert_id:
            return candidate
    return None


def _fetch_child_of(
    collection: str,
    join_key: str,
    parent_id: str | None,
    correlation_id: str | None,
) -> list[MemoryRecord]:
    """Fetch one parent's children: exact join first, correlation as fallback."""
    records: list[MemoryRecord] = []
    if parent_id:
        records = _search(
            collection,
            MemoryQuery(
                metadata={join_key: parent_id},
                order_by="created_at",
                descending=True,
            ),
        )
    if records or not correlation_id:
        return records
    # Reaches records whose join key was never written to metadata. ChildIndex
    # discards a run-scoped match that more than one parent claims, so a
    # multi-event run resolves to nothing here rather than to the wrong record.
    return _search(
        collection,
        MemoryQuery(
            correlation_id=correlation_id, order_by="created_at", descending=True
        ),
    )


def load_alert(alert_id: str) -> dict[str, Any] | None:
    """Return one projected alert with its chain resolved, or None.

    Walks detection -> analysis -> decision -> response for this alert alone.
    The single-alert endpoints used to call ``load_frontend_state_from_memory()``,
    which read a hundred detections, a hundred analyses, a hundred decisions and
    two hundred responses, projected every one of them, and then linear-searched
    the result for one id.
    """
    ensure_runtime()
    if platform.memory_provider is None:
        return None

    detection = find_detection_record(alert_id)
    if detection is None:
        return None

    detection_id = reference_id(detection, "detection_id")
    analyses = _fetch_child_of(
        "analysis", "detection_id", detection_id, detection.correlation_id
    )

    analysis_ids = [
        value
        for value in (reference_id(record, "analysis_id") for record in analyses)
        if value
    ]
    decisions = _fetch_child_of(
        "decisions",
        "analysis_id",
        analysis_ids[0] if analysis_ids else None,
        detection.correlation_id,
    )
    if not decisions and detection_id:
        decisions = _fetch_child_of(
            "decisions", "detection_id", detection_id, detection.correlation_id
        )

    decision_ids = [
        value
        for value in (reference_id(record, "decision_id") for record in decisions)
        if value
    ]
    responses = _fetch_child_of(
        RESPONSE_COLLECTION,
        "decision_id",
        decision_ids[0] if decision_ids else None,
        detection.correlation_id,
    )

    alerts = build_alerts_from_memory_records(
        [detection], analyses, decisions, responses
    )
    return alerts[0] if alerts else None


def load_alert_detail(alert_id: str) -> dict[str, Any] | None:
    """Return one alert's full detail payload, or None when it does not exist."""
    alert = load_alert(alert_id)
    if alert is None:
        return None
    return build_alert_detail_payload(
        alert, alert.get("analysis"), alert.get("response_action")
    )


def load_frontend_state_from_memory() -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Return (alerts, analyses, containments) projected from stored records.

    Returns empty lists when memory is unavailable or holds nothing. It used to
    fall back to the MOCK_ALERTS / MOCK_ANALYSES / MOCK_BLOCKED_IPS module
    globals, which meant an unreachable memory provider was indistinguishable
    from a quiet network: the dashboard showed fabricated alerts and an analyst
    had no way to tell they were not real.
    """
    ensure_runtime()
    if platform.memory_provider is None:
        return [], [], []

    try:
        detection_records, analysis_records, decision_records, response_records = (
            fetch_alert_chain()
        )
    except Exception as exc:
        # Surfaced rather than silently swallowed: an empty dashboard caused by
        # a broken memory provider must be attributable.
        print(f"[WARN] Could not read platform memory: {exc}")
        return [], [], []

    alerts = build_alerts_from_memory_records(
        detection_records, analysis_records, decision_records, response_records
    )
    if not alerts:
        return [], [], []

    analyses = [
        view for view in map(analysis_view, analysis_records) if view is not None
    ]
    # Containments are projected from real ResponseResult records.
    return alerts, analyses, active_containments()


def load_response_records(limit: int = 200) -> list[dict[str, Any]]:
    """Return persisted ResponseResult payloads, newest first."""
    ensure_runtime()
    if platform.memory_provider is None:
        return []
    try:
        hits = platform.memory_provider.search(
            RESPONSE_COLLECTION,
            MemoryQuery(limit=limit, order_by="created_at", descending=True),
        )
    except Exception:
        return []
    return [
        hit.record.content
        for hit in hits
        if isinstance(hit.record.content, dict)
    ]


def rehydrate_response(record: dict[str, Any]) -> ResponseResult:
    """Rebuild a ResponseResult from its persisted memory payload.

    Only the fields a revert needs are reconstructed — the action, the
    executor that performed it, and the revert token. The rebuilt object is
    an input to ResponseAgent.revert(), never a replacement for the original
    audit record, which stays immutable in memory.
    """
    return ResponseResult(
        response_id=record["response_id"],
        decision_id=record["decision_id"],
        correlation_id=record["correlation_id"],
        trace_id=record["trace_id"],
        action=Action(
            action_type=ActionType(record["action_type"]),
            target=ActionTarget(
                target_type=record["target_type"],
                target_value=record["target_value"],
            ),
            parameters=ActionParameters(),
        ),
        original_action=Action(
            action_type=ActionType(record["action_type"]),
            target=ActionTarget(
                target_type=record["target_type"],
                target_value=record["target_value"],
            ),
            parameters=ActionParameters(),
        ),
        status=ResponseStatus(record["status"]),
        guard_verdict=GuardVerdict(record["guard_verdict"]),
        guard_rule=record["guard_rule"],
        guard_reason=record["guard_reason"],
        engine_trust_tier=EngineTrustTier(record["engine_trust_tier"]),
        decision_engine=record["decision_engine"],
        executor_name=record.get("executor_name"),
        executor_version=record.get("executor_version") or "1.0.0",
        idempotency_key=record.get("idempotency_key") or record["response_id"],
        external_reference=record.get("external_reference"),
        revert_token=record.get("revert_token"),
        response_duration_ms=0.0,
        audit=AuditMetadata(
            created_by="response_agent",
            updated_by="api",
            source_system="response_pipeline",
        ),
    )


def active_containments() -> list[dict[str, Any]]:
    """Project currently-enforced containments from response history.

    A containment is active when it was executed and has not since been
    reverted. This replaces the former MOCK_BLOCKED_IPS list: what the
    dashboard shows is now derived from what the ResponseAgent actually did.
    """
    records = load_response_records()
    reverted = {
        rec.get("reverts_response_id")
        for rec in records
        if rec.get("status") == ResponseStatus.REVERTED.value
    }
    containment_actions = {
        ActionType.BLOCK_IP.value,
        ActionType.ISOLATE_HOST.value,
        ActionType.RATE_LIMIT.value,
    }
    active: list[dict[str, Any]] = []
    for rec in records:
        if rec.get("status") != ResponseStatus.EXECUTED.value:
            continue
        if rec.get("action_type") not in containment_actions:
            continue
        if rec.get("response_id") in reverted:
            continue
        active.append(
            {
                "id":          rec.get("response_id"),
                "ip":          rec.get("target_value"),
                "reason":      rec.get("guard_reason"),
                "action":      rec.get("action_type"),
                "decision_id": rec.get("decision_id"),
                "executor":    rec.get("executor_name"),
                "expires_at":  rec.get("expires_at"),
                "created_at":  rec.get("executed_at"),
            }
        )
    return active
