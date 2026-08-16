"""Feeds streamed flows into the agent pipeline.

    Redis Stream ──► FlowConsumer ──► SecurityEvent[] ──► CoordinatorAgent

One batch becomes one coordinated graph run: a single correlation_id carrying
N events, which the coordinator drains stage by stage. That is exactly the
shape CoordinatorAgent was built for — before it, a run accepting N events
processed one and silently dropped the rest.

BATCH SIZE IS BOUNDED BY THE COORDINATOR'S BUDGET
-------------------------------------------------
Each event costs one dispatch per pipeline stage (detection, analysis,
decision, response), so N events need N × 4 coordinator dispatches. With the
default `coordinator_max_iterations` of 100, a 50-event batch would exhaust
the budget after 25 events and end the run with the remainder still pending.

That failure is *safe* — the coordinator reports outstanding work rather than
dropping it — but it is silent waste. The bridge therefore caps its own batch
at `max_events_per_run` and never hands the coordinator more than it can
drain.
"""
from __future__ import annotations

import logging
from dataclasses import asdict, dataclass

from cyber_surakshya.platform.identifiers.correlation import CorrelationContext
from cyber_surakshya.platform.state import create_initial_state
from ingestion.bridge.event_builder import EventBuilder

logger = logging.getLogger(__name__)

# detection → analysis → decision → response
PIPELINE_STAGES = 4

# Fits the default coordinator budget of 100 dispatches with headroom.
DEFAULT_MAX_EVENTS_PER_RUN = 20


@dataclass
class BridgeStats:
    """Counters exposed so every discarded flow has a number attached."""

    batches_run:      int = 0
    flows_consumed:   int = 0
    events_built:     int = 0
    events_dropped:   int = 0
    flows_acked:      int = 0
    runs_failed:      int = 0
    detections:       int = 0
    responses:        int = 0

    def as_dict(self) -> dict[str, int]:
        return asdict(self)


class PipelineBridge:
    """Consumes flows and runs them through the coordinated agent graph."""

    def __init__(
        self,
        consumer,
        runtime,
        *,
        event_builder: EventBuilder | None = None,
        max_events_per_run: int = DEFAULT_MAX_EVENTS_PER_RUN,
        coordinator_budget: int | None = None,
    ) -> None:
        """
        Args:
            consumer: a FlowConsumer.
            runtime: a GraphRuntime with a registered coordinator.
            max_events_per_run: hard cap on events per graph run.
            coordinator_budget: the coordinator's max_iterations. When given,
                the batch is capped at `budget // PIPELINE_STAGES` so a
                configuration mismatch cannot silently strand events.
        """
        self.consumer      = consumer
        self.runtime       = runtime
        self.event_builder = event_builder or EventBuilder()
        self.stats         = BridgeStats()

        capped = max_events_per_run
        if coordinator_budget is not None:
            drainable = max(1, coordinator_budget // PIPELINE_STAGES)
            if drainable < capped:
                logger.info(
                    "bridge_batch_capped_to_coordinator_budget",
                    extra={
                        "requested": capped,
                        "applied":   drainable,
                        "budget":    coordinator_budget,
                    },
                )
                capped = drainable
        self.max_events_per_run = capped

    # ── Draining ──────────────────────────────────────────────────────────────

    def run_once(self) -> int:
        """Consume one batch and run it through the pipeline.

        Returns the number of events processed. Zero means the stream was
        idle, which is a normal state rather than an error.

        Flows are acknowledged only after the graph run completes, so a crash
        mid-run leaves them pending for another consumer to reclaim.
        """
        flows = self.consumer.read_with_recovery(count=self.max_events_per_run)
        if not flows:
            return 0

        self.stats.flows_consumed += len(flows)
        context = CorrelationContext.create()
        events = self.event_builder.build_many(
            flows,
            correlation_id=context.correlation_id,
            trace_id=context.trace_id,
        )
        dropped = len(flows) - len(events)
        if dropped:
            self.stats.events_dropped += dropped
            logger.warning(
                "bridge_flows_dropped",
                extra={"dropped": dropped, "consumed": len(flows)},
            )
        if not events:
            # Nothing buildable. Acknowledge so the batch is not redelivered
            # forever, having already counted the loss.
            self.consumer.ack_all(flows)
            return 0

        self.stats.events_built += len(events)

        state = create_initial_state(context=context)
        state.security_events = events

        try:
            result = self.runtime.execute(state)
        except Exception as exc:
            # Unacknowledged: another consumer reclaims and retries, and the
            # dead-letter path catches anything that fails repeatedly.
            self.stats.runs_failed += 1
            logger.exception(
                "bridge_pipeline_run_failed",
                extra={"events": len(events), "error": str(exc)[:300]},
            )
            return 0

        self.stats.batches_run += 1
        self.stats.detections += len(result.detection_results)
        self.stats.responses += len(result.response_results)
        acked = self.consumer.ack_all(flows)
        self.stats.flows_acked += acked

        coordinator = result.metadata.get("coordinator_agent", {})
        logger.info(
            "bridge_batch_completed",
            extra={
                "events":       len(events),
                "detections":   len(result.detection_results),
                "decisions":    len(result.decision_results),
                "responses":    len(result.response_results),
                "acked":        acked,
                "coordinator":  coordinator.get("status"),
                "pending":      coordinator.get("pending_total"),
                "errors":       len(result.errors),
            },
        )
        self._warn_on_incomplete_drain(coordinator, len(events))
        return len(events)

    def drain(self, *, max_batches: int = 10) -> int:
        """Run batches until the stream is idle or the batch limit is reached."""
        total = 0
        for _ in range(max_batches):
            processed = self.run_once()
            if processed == 0:
                break
            total += processed
        return total

    # ── Diagnostics ───────────────────────────────────────────────────────────

    def status(self) -> dict:
        """Bridge and stream health for the control plane."""
        return {
            "max_events_per_run": self.max_events_per_run,
            "pending":            self.consumer.pending_count(),
            "consumer":           self.consumer.consumer_name,
            "bridge":             self.stats.as_dict(),
            "consumer_stats":     self.consumer.stats.as_dict(),
        }

    @staticmethod
    def _warn_on_incomplete_drain(coordinator: dict, events: int) -> None:
        """Surface work the coordinator could not finish.

        The coordinator already reports outstanding work rather than dropping
        it, but nothing reads that report unless the bridge raises it here.
        """
        pending = coordinator.get("pending_total") or 0
        if pending:
            logger.warning(
                "bridge_batch_left_work_pending",
                extra={
                    "events":         events,
                    "pending_total":  pending,
                    "stalled_stages": coordinator.get("stalled_stages"),
                    "reason":         coordinator.get("reason"),
                },
            )
