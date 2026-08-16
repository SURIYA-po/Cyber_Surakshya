"""Coordinator Agent LangGraph node.

Responsibilities (strict boundary):
  DOES:
    - Compute outstanding work per pipeline stage from PlatformSharedState
    - Choose the next node to run, or END
    - Drain the queue so every event traverses the full pipeline
    - Detect stalled stages and stop dispatching to them
    - Enforce an iteration budget so a run always terminates
    - Route a resumable AWAITING_APPROVAL decision back to ResponseAgent, once
    - Record a run summary in metadata["coordinator_agent"]

  DOES NOT:
    - Perform detection, analysis, decision, or response work
    - Read or interpret domain payloads (features, labels, risk, actions)
    - Append to any result list — it is the only agent that adds no records
    - Touch an executor, a memory provider, or an LLM

The coordinator exists because every agent processes exactly one pending item
per invocation while the graph was a single linear pass, so a run accepting N
events processed one and silently dropped N-1. See docs/coordinator_agent.md.

All bookkeeping lives in state metadata rather than on the instance: app.py
holds agents as module-level singletons shared across requests and threads.
"""
from __future__ import annotations

import logging
from typing import Any, Iterable

from agents.coordinator.routing import (
    COORDINATOR_METADATA_KEY,
    PIPELINE_ORDER,
    CoordinatorMemo,
    RouteTarget,
    decide_route,
    detect_stall,
    find_duplicate_event_ids,
)
from cyber_surakshya.platform.state import PlatformSharedState, PlatformStateModel

logger = logging.getLogger(__name__)

DEFAULT_MAX_ITERATIONS = 100


class CoordinatorAgent:
    """LangGraph node that decides which agent runs next.

    Used as a pair: ``__call__`` is the node handler that computes and records
    the routing decision; ``route`` is the conditional-edge function that
    reads it back.
    """

    def __init__(
        self,
        *,
        max_iterations: int = DEFAULT_MAX_ITERATIONS,
        stages: Iterable[RouteTarget | str] | None = None,
        agent_name: str = "coordinator_agent",
    ) -> None:
        """
        Args:
            max_iterations: dispatch budget per run; a backstop behind stall
                detection.
            stages: the pipeline stages this graph actually registers. Defaults
                to the full pipeline. A coordinator that routes to an
                unregistered node would raise a bare KeyError inside LangGraph
                mid-run, so a partial graph must declare what it has.
        """
        if max_iterations < 1:
            raise ValueError("max_iterations must be at least 1.")
        self.max_iterations = max_iterations
        self.agent_name     = agent_name
        self.stages         = self._normalize_stages(stages)

    @staticmethod
    def _normalize_stages(
        stages: Iterable[RouteTarget | str] | None,
    ) -> frozenset[RouteTarget]:
        if stages is None:
            return frozenset(PIPELINE_ORDER)
        resolved: set[RouteTarget] = set()
        for stage in stages:
            target = stage if isinstance(stage, RouteTarget) else RouteTarget(stage)
            if target is RouteTarget.END:
                continue
            resolved.add(target)
        if not resolved:
            raise ValueError("At least one routable stage is required.")
        return frozenset(resolved)

    @property
    def routable_targets(self) -> tuple[str, ...]:
        """Node names this coordinator may dispatch to, for build-time checks."""
        return tuple(sorted(stage.value for stage in self.stages))

    # ── Node handler ──────────────────────────────────────────────────────────

    def __call__(self, state: PlatformSharedState) -> PlatformSharedState:
        """Evaluate outstanding work and record the next routing decision."""
        try:
            state_model = PlatformStateModel.from_graph_state(state)
            memo        = CoordinatorMemo.from_metadata(state_model.metadata)

            # A stage that ran without producing output is broken, not busy.
            # Excluding it converts an infinite loop into a reported failure.
            stall_reason = detect_stall(state_model, memo)
            if stall_reason is not None and memo.last_stage is not None:
                memo.record_stall(memo.last_stage, stall_reason)
                logger.warning(
                    "coordinator_stage_stalled",
                    extra={
                        "agent":          self.agent_name,
                        "stage":          memo.last_stage,
                        "reason":         stall_reason,
                        "correlation_id": state_model.correlation_id,
                    },
                )

            self._suppress_duplicate_events(state_model, memo)

            decision, queue = decide_route(
                state_model,
                memo,
                max_iterations=self.max_iterations,
                available_stages=self.stages,
            )

            if decision.is_terminal:
                logger.info(
                    "coordinator_run_completed",
                    extra={
                        "agent":          self.agent_name,
                        "iterations":     memo.iteration,
                        "dispatches":     dict(memo.dispatches),
                        "stalled_stages": sorted(memo.stalled_stages),
                        "pending_total":  queue.total,
                        "reason":         decision.reason,
                        "correlation_id": state_model.correlation_id,
                    },
                )
                memo.last_stage        = None
                memo.last_output_count = None
            else:
                stage = decision.target.value
                memo.iteration += 1
                memo.dispatches[stage] = memo.dispatches.get(stage, 0) + 1
                memo.last_stage        = stage
                memo.last_output_count = self._output_count(state_model, decision.target)
                if decision.target is RouteTarget.RESPONSE and queue.resumable_response \
                        and not queue.pending_response:
                    # Record the resume attempt before it happens: an approval
                    # that never arrives must not be retried forever.
                    memo.resume_attempted.update(queue.resumable_response)

                logger.info(
                    "coordinator_dispatch",
                    extra={
                        "agent":          self.agent_name,
                        "iteration":      memo.iteration,
                        "next_node":      stage,
                        "reason":         decision.reason,
                        "pending":        queue.as_counts(),
                        "correlation_id": state_model.correlation_id,
                    },
                )

            return PlatformSharedState(
                correlation_id=state_model.correlation_id,
                trace_id=state_model.trace_id,
                session_id=state_model.session_id,
                metadata={
                    **state_model.metadata,
                    COORDINATOR_METADATA_KEY: memo.to_metadata(decision, queue),
                },
            )

        except Exception as exc:
            logger.exception(
                "coordinator_agent_failed",
                extra={
                    "agent":      self.agent_name,
                    "error_type": type(exc).__name__,
                },
            )
            return self._error_update(state, exc)

    # ── Conditional edge function ─────────────────────────────────────────────

    def route(self, state: PlatformSharedState) -> str:
        """Return the next node name for LangGraph's conditional edges.

        Reads the decision ``__call__`` just recorded. Falls back to
        re-deriving it if the metadata is missing, so a routing failure
        degrades to ending the run rather than raising mid-graph.
        """
        try:
            metadata = state.get("metadata") if isinstance(state, dict) else {}
            recorded = (metadata or {}).get(COORDINATOR_METADATA_KEY, {})
            next_node = recorded.get("next_node")
            if next_node:
                return next_node

            state_model = PlatformStateModel.from_graph_state(state)
            memo        = CoordinatorMemo.from_metadata(state_model.metadata)
            decision, _ = decide_route(
                state_model,
                memo,
                max_iterations=self.max_iterations,
                available_stages=self.stages,
            )
            return decision.target.value
        except Exception as exc:
            logger.exception(
                "coordinator_route_failed",
                extra={"agent": self.agent_name, "error_type": type(exc).__name__},
            )
            return RouteTarget.END.value

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _output_count(state: PlatformStateModel, target: RouteTarget) -> int | None:
        """Current size of the list the target stage appends to."""
        from agents.coordinator.routing import STAGE_OUTPUT_FIELD

        field_name = STAGE_OUTPUT_FIELD.get(target)
        if field_name is None:
            return None
        return len(getattr(state, field_name))

    def _suppress_duplicate_events(
        self,
        state: PlatformStateModel,
        memo: CoordinatorMemo,
    ) -> None:
        """Exclude exact-identity duplicate events from the detection queue.

        Identity duplicates only. Flows with identical content are left alone
        on purpose — repeated identical flows are the signal, not noise.
        """
        duplicates = find_duplicate_event_ids(state)
        new = set(duplicates) - memo.suppressed_event_ids
        if not new:
            return
        memo.suppressed_event_ids.update(new)
        memo.anomalies.append(
            f"suppressed {len(new)} duplicate event id(s) from the detection queue"
        )
        logger.warning(
            "coordinator_duplicate_events_suppressed",
            extra={
                "agent":          self.agent_name,
                "count":          len(new),
                "correlation_id": state.correlation_id,
            },
        )

    def _error_update(
        self,
        state: PlatformSharedState,
        error: Exception,
    ) -> PlatformSharedState:
        """Return an error update that also halts the run.

        A coordinator that cannot decide where to go must end the run rather
        than leave the router guessing — ``next_node`` is set to END.
        """
        existing: dict[str, Any] = {}
        try:
            existing = dict(state.get("metadata") or {}) if isinstance(state, dict) else {}
        except Exception:
            existing = {}

        return PlatformSharedState(
            errors=[f"{self.agent_name}: {error}"],
            metadata={
                **existing,
                COORDINATOR_METADATA_KEY: {
                    "status":     "failed",
                    "error_type": type(error).__name__,
                    "next_node":  RouteTarget.END.value,
                    "reason":     "coordinator failed; ending run",
                },
            },
        )
