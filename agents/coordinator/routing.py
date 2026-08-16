"""Routing domain for the CoordinatorAgent.

Pure functions over platform state. No I/O, no LangGraph imports, no side
effects — the entire routing policy is unit-testable without a graph, a
memory provider, or a mock.

Two ideas carry the module:

``WorkQueue``      — what work is outstanding at each pipeline stage.
``CoordinatorMemo`` — what has happened so far this run. The memo lives in
                      ``metadata["coordinator_agent"]`` rather than on the
                      agent instance, because app.py holds agents as
                      module-level singletons shared across requests and
                      threads; per-instance counters would leak between runs.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from cyber_surakshya.platform.schemas.response_result import ResponseStatus
from cyber_surakshya.platform.state import PlatformStateModel

# Key under which the coordinator stores its run memo in state metadata.
COORDINATOR_METADATA_KEY = "coordinator_agent"

# Sentinel returned to LangGraph's conditional edge map to finish the run.
END_ROUTE = "__end__"


class RouteTarget(str, Enum):
    """Nodes the coordinator can dispatch to."""

    DETECTION = "detection"
    ANALYSIS  = "analysis"
    DECISION  = "decision"
    RESPONSE  = "response"
    END       = END_ROUTE


# Pipeline order. The first stage with unstalled pending work wins, which
# drains breadth-first: every detection, then every analysis, and so on.
PIPELINE_ORDER: tuple[RouteTarget, ...] = (
    RouteTarget.DETECTION,
    RouteTarget.ANALYSIS,
    RouteTarget.DECISION,
    RouteTarget.RESPONSE,
)

# The state list each stage appends to. A dispatch that leaves this list the
# same length made no progress — that is the stall signal.
STAGE_OUTPUT_FIELD: dict[RouteTarget, str] = {
    RouteTarget.DETECTION: "detection_results",
    RouteTarget.ANALYSIS:  "analysis_results",
    RouteTarget.DECISION:  "decision_results",
    RouteTarget.RESPONSE:  "response_results",
}


# ── Work queue ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class WorkQueue:
    """Outstanding work per pipeline stage, derived from state."""

    pending_detection: tuple[str, ...] = ()
    pending_analysis:  tuple[str, ...] = ()
    pending_decision:  tuple[str, ...] = ()
    pending_response:  tuple[str, ...] = ()
    resumable_response: tuple[str, ...] = ()

    def pending_for(self, stage: RouteTarget) -> tuple[str, ...]:
        """Return the outstanding item IDs for a stage."""
        return {
            RouteTarget.DETECTION: self.pending_detection,
            RouteTarget.ANALYSIS:  self.pending_analysis,
            RouteTarget.DECISION:  self.pending_decision,
            RouteTarget.RESPONSE:  self.pending_response,
        }.get(stage, ())

    @property
    def total(self) -> int:
        """Total outstanding items, including resumable responses."""
        return (
            len(self.pending_detection)
            + len(self.pending_analysis)
            + len(self.pending_decision)
            + len(self.pending_response)
            + len(self.resumable_response)
        )

    def as_counts(self) -> dict[str, int]:
        """Serializable summary for the run report."""
        return {
            "detection":          len(self.pending_detection),
            "analysis":           len(self.pending_analysis),
            "decision":           len(self.pending_decision),
            "response":           len(self.pending_response),
            "response_resumable": len(self.resumable_response),
        }


def build_work_queue(
    state: PlatformStateModel,
    *,
    resume_attempted: frozenset[str] = frozenset(),
    suppressed_event_ids: frozenset[str] = frozenset(),
) -> WorkQueue:
    """Compute outstanding work at every stage.

    ``resume_attempted`` excludes decisions whose approval-resume has already
    been tried this run, so an unapproved decision is retried at most once.
    """
    detected_event_ids   = {d.event_id for d in state.detection_results}
    analysed_detections  = {a.detection_id for a in state.analysis_results}
    decided_analyses     = {d.analysis_id for d in state.decision_results}

    # A decision is "responded" only once it has a response that is not
    # AWAITING_APPROVAL — that status is explicitly resumable, not terminal.
    responses_by_decision: dict[str, list[ResponseStatus]] = {}
    for response in state.response_results:
        responses_by_decision.setdefault(response.decision_id, []).append(response.status)

    pending_response:   list[str] = []
    resumable_response: list[str] = []
    for decision in state.decision_results:
        statuses = responses_by_decision.get(decision.decision_id)
        if not statuses:
            pending_response.append(decision.decision_id)
        elif all(s is ResponseStatus.AWAITING_APPROVAL for s in statuses):
            if decision.decision_id not in resume_attempted:
                resumable_response.append(decision.decision_id)

    return WorkQueue(
        pending_detection=tuple(
            event.event_id
            for event in state.security_events
            if event.event_id not in detected_event_ids
            and event.event_id not in suppressed_event_ids
        ),
        pending_analysis=tuple(
            detection.detection_id
            for detection in state.detection_results
            if detection.detection_id not in analysed_detections
        ),
        pending_decision=tuple(
            analysis.analysis_id
            for analysis in state.analysis_results
            if analysis.analysis_id not in decided_analyses
        ),
        pending_response=tuple(pending_response),
        resumable_response=tuple(resumable_response),
    )


def find_duplicate_event_ids(state: PlatformStateModel) -> tuple[str, ...]:
    """Return event IDs that appear more than once in the state.

    Exact-identity duplicates only. Flows with identical *content* are
    deliberately NOT collapsed: repeated identical flows are the signal an IDS
    exists to catch, and suppressing them would hide volumetric floods and
    credential-stuffing loops. Content-level aggregation belongs in a threat
    aggregation component with an explicit window and counter.
    """
    seen: set[str] = set()
    duplicates: list[str] = []
    for event in state.security_events:
        if event.event_id in seen:
            duplicates.append(event.event_id)
        else:
            seen.add(event.event_id)
    return tuple(duplicates)


# ── Run memo ──────────────────────────────────────────────────────────────────


@dataclass
class CoordinatorMemo:
    """Per-run coordinator bookkeeping, carried inside state metadata."""

    iteration:            int            = 0
    dispatches:           dict[str, int] = field(default_factory=dict)
    stalled_stages:       set[str]       = field(default_factory=set)
    resume_attempted:     set[str]       = field(default_factory=set)
    suppressed_event_ids: set[str]       = field(default_factory=set)
    last_stage:           str | None     = None
    last_output_count:    int | None     = None
    anomalies:            list[str]      = field(default_factory=list)

    @classmethod
    def from_metadata(cls, metadata: dict[str, Any]) -> CoordinatorMemo:
        """Rebuild the memo from state metadata, tolerating a fresh run."""
        raw = metadata.get(COORDINATOR_METADATA_KEY)
        if not isinstance(raw, dict):
            return cls()
        return cls(
            iteration=int(raw.get("iteration", 0)),
            dispatches=dict(raw.get("dispatches") or {}),
            stalled_stages=set(raw.get("stalled_stages") or []),
            resume_attempted=set(raw.get("resume_attempted") or []),
            suppressed_event_ids=set(raw.get("suppressed_event_ids") or []),
            last_stage=raw.get("last_stage"),
            last_output_count=raw.get("last_output_count"),
            anomalies=list(raw.get("anomalies") or []),
        )

    def to_metadata(self, decision: RouteDecision, queue: WorkQueue) -> dict[str, Any]:
        """Serialize the memo plus the current routing decision."""
        return {
            "status":               "completed" if decision.is_terminal else "routing",
            "iteration":            self.iteration,
            "next_node":            decision.target.value,
            "reason":               decision.reason,
            "dispatches":           dict(self.dispatches),
            "stalled_stages":       sorted(self.stalled_stages),
            "resume_attempted":     sorted(self.resume_attempted),
            "suppressed_event_ids": sorted(self.suppressed_event_ids),
            "last_stage":           self.last_stage,
            "last_output_count":    self.last_output_count,
            "pending":              queue.as_counts(),
            "pending_total":        queue.total,
            "anomalies":            list(self.anomalies),
        }

    def record_stall(self, stage: str, reason: str) -> None:
        """Mark a stage as making no progress and stop dispatching to it."""
        self.stalled_stages.add(stage)
        self.anomalies.append(reason)


# ── Routing decision ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RouteDecision:
    """Where the coordinator sends the run next, and why."""

    target: RouteTarget
    reason: str

    @property
    def is_terminal(self) -> bool:
        return self.target is RouteTarget.END


def detect_stall(
    state: PlatformStateModel,
    memo: CoordinatorMemo,
) -> str | None:
    """Return a stall reason when the previously dispatched stage made no progress.

    This is the guarantee that turns a live-lock into a visible failure. Agents
    swallow their own exceptions and return without producing a result, so a
    naive "route while work is pending" loop would dispatch to a broken stage
    forever.
    """
    if memo.last_stage is None or memo.last_output_count is None:
        return None
    try:
        stage = RouteTarget(memo.last_stage)
    except ValueError:
        return None
    field_name = STAGE_OUTPUT_FIELD.get(stage)
    if field_name is None:
        return None

    current = len(getattr(state, field_name))
    if current > memo.last_output_count:
        return None
    return (
        f"stage {stage.value!r} produced no new {field_name} "
        f"(count stayed at {current}); excluding it from further routing"
    )


def decide_route(
    state: PlatformStateModel,
    memo: CoordinatorMemo,
    *,
    max_iterations: int,
    available_stages: frozenset[RouteTarget] = frozenset(PIPELINE_ORDER),
) -> tuple[RouteDecision, WorkQueue]:
    """Choose the next node for this run.

    Precedence: iteration budget, then stage availability, then stall
    exclusion, then pipeline order.

    ``available_stages`` names the nodes actually registered on the graph.
    Routing to an absent node would raise a bare KeyError inside LangGraph's
    branch resolution, mid-run and with no attribution, so a partial pipeline
    simply skips the stages it does not have.

    Returns the decision alongside the queue it was derived from so the caller
    can report both without recomputing.
    """
    queue = build_work_queue(
        state,
        resume_attempted=frozenset(memo.resume_attempted),
        suppressed_event_ids=frozenset(memo.suppressed_event_ids),
    )

    if memo.iteration >= max_iterations:
        return (
            RouteDecision(
                RouteTarget.END,
                f"iteration budget of {max_iterations} exhausted with "
                f"{queue.total} item(s) still pending",
            ),
            queue,
        )

    for stage in PIPELINE_ORDER:
        if stage not in available_stages:
            continue
        if stage.value in memo.stalled_stages:
            continue
        pending = queue.pending_for(stage)
        if pending:
            return (
                RouteDecision(
                    stage,
                    f"{len(pending)} item(s) pending at stage {stage.value!r}",
                ),
                queue,
            )

    if (
        queue.resumable_response
        and RouteTarget.RESPONSE in available_stages
        and RouteTarget.RESPONSE.value not in memo.stalled_stages
    ):
        return (
            RouteDecision(
                RouteTarget.RESPONSE,
                f"{len(queue.resumable_response)} decision(s) awaiting approval; "
                "attempting resume",
            ),
            queue,
        )

    if memo.stalled_stages:
        return (
            RouteDecision(
                RouteTarget.END,
                f"no routable work remaining; stalled stage(s): "
                f"{sorted(memo.stalled_stages)}",
            ),
            queue,
        )

    return RouteDecision(RouteTarget.END, "all pipeline work drained"), queue
