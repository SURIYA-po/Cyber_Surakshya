"""Flow producer — publishes normalized flows onto a bounded Redis Stream.

Redis Streams is the right transport here for durability across a consumer
restart, consumer groups with pending-entry recovery, and natural backpressure
through a bounded stream. It is emphatically **not** a security control: Redis
binds to every interface with no authentication by default. Authentication,
ACL scoping, and network isolation are configured in `docker/redis/`.

Two properties this module must have:

**Fail closed.** An unreachable Redis refuses to start rather than accepting
flows and discarding them. Silent loss is the one failure this layer must not
have — a dropped flow is an attack the platform never saw and never reported.

**Deduplicate by flow_id.** Replaying a pcap must not fabricate a volumetric
attack. The platform deliberately treats repeated identical flows as signal,
so genuine duplicates have to be suppressed before they reach it.
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from typing import Any, Iterable

from ingestion.flows.normalizer import NormalizedFlow
from ingestion.stream.client import RedisUnavailableError, connect

logger = logging.getLogger(__name__)


@dataclass
class ProducerStats:
    """Counters exposed so loss and suppression are visible, never inferred."""

    published:   int = 0
    duplicates:  int = 0
    failed:      int = 0

    def as_dict(self) -> dict[str, int]:
        return asdict(self)


class FlowProducer:
    """Publishes NormalizedFlow records to the ingest stream."""

    def __init__(self, policy, *, client=None) -> None:
        """
        Args:
            policy: a StreamPolicy.
            client: an existing Redis client. Injected in tests; created from
                the policy otherwise.
        """
        self.policy = policy
        self.client = client if client is not None else connect(policy)
        self.stats  = ProducerStats()

    # ── Publishing ────────────────────────────────────────────────────────────

    def publish(self, flow: NormalizedFlow) -> str | None:
        """Publish one flow. Returns its stream ID, or None when suppressed.

        Raises:
            RedisUnavailableError: the flow could not be published and
                ``fail_closed`` is set. The caller must not treat the flow as
                delivered.
        """
        if self._is_duplicate(flow.flow_id):
            self.stats.duplicates += 1
            logger.debug(
                "flow_duplicate_suppressed", extra={"flow_id": flow.flow_id[:12]}
            )
            return None

        entry = self._encode(flow)
        try:
            message_id = self.client.xadd(
                self.policy.stream_key,
                entry,
                maxlen=self.policy.max_length,
                approximate=self.policy.approximate_trim,
            )
        except Exception as exc:
            self.stats.failed += 1
            logger.error(
                "flow_publish_failed",
                extra={"flow_id": flow.flow_id[:12], "error": str(exc)},
            )
            if self.policy.fail_closed:
                raise RedisUnavailableError(
                    f"Could not publish flow {flow.flow_id[:12]}: {exc}"
                ) from exc
            return None

        self.stats.published += 1
        return message_id if isinstance(message_id, str) else message_id.decode()

    def publish_many(self, flows: Iterable[NormalizedFlow]) -> int:
        """Publish a batch. Returns the number actually written."""
        written = 0
        for flow in flows:
            if self.publish(flow) is not None:
                written += 1
        if written:
            logger.info(
                "flows_published",
                extra={
                    "written":    written,
                    "duplicates": self.stats.duplicates,
                    "stream":     self.policy.stream_key,
                },
            )
        return written

    # ── Introspection ─────────────────────────────────────────────────────────

    def stream_length(self) -> int:
        """Current stream depth — the backlog the pipeline has yet to drain."""
        try:
            return int(self.client.xlen(self.policy.stream_key))
        except Exception:
            return 0

    def backlog_ratio(self) -> float:
        """Depth as a fraction of the cap. Approaching 1.0 means eviction.

        Redis trims silently, so this is the only warning a consumer gets that
        flows are about to be lost to backpressure.
        """
        if self.policy.max_length <= 0:
            return 0.0
        return min(1.0, self.stream_length() / self.policy.max_length)

    # ── Private ───────────────────────────────────────────────────────────────

    def _is_duplicate(self, flow_id: str) -> bool:
        """Claim a flow_id for the dedup window. False means "first sighting".

        Uses SET NX EX, so the claim and the check are one atomic operation —
        two producers racing on the same flow cannot both win. A Redis failure
        here returns False (not a duplicate): losing a flow is worse than
        processing one twice, and the consumer is idempotent anyway.
        """
        if not flow_id or self.policy.dedup_ttl_seconds <= 0:
            return False
        key = f"{self.policy.dedup_key_prefix}{flow_id}"
        try:
            claimed = self.client.set(
                key, "1", nx=True, ex=self.policy.dedup_ttl_seconds
            )
        except Exception as exc:
            logger.warning("flow_dedup_check_failed", extra={"error": str(exc)})
            return False
        return not bool(claimed)

    @staticmethod
    def _encode(flow: NormalizedFlow) -> dict[str, Any]:
        """Flatten a flow into stream fields.

        Features travel as one JSON blob rather than 42 separate fields: it
        keeps the entry compact, and it guarantees the consumer reconstructs
        exactly the 42 the producer sent rather than whatever fields happen to
        be present.
        """
        return {
            "flow_id":          flow.flow_id,
            "features":         json.dumps(flow.features, separators=(",", ":")),
            "source_ip":        flow.source_ip or "",
            "destination_ip":   flow.destination_ip or "",
            "source_port":      str(flow.source_port if flow.source_port is not None else ""),
            "destination_port": str(
                flow.destination_port if flow.destination_port is not None else ""
            ),
            "protocol":         str(flow.protocol if flow.protocol is not None else ""),
            "timestamp":        flow.timestamp or "",
            "warnings":         json.dumps(list(flow.warnings)) if flow.warnings else "",
        }
