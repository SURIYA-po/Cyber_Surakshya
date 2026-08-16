"""Flow consumer — reads the ingest stream with at-least-once delivery.

Consumer-group semantics give the two properties the pipeline needs:

**Lose nothing.** A message is acknowledged only after the caller confirms it
was processed. A consumer that dies mid-batch leaves its messages pending, and
another consumer reclaims them via XAUTOCLAIM.

**Replay nothing.** Acknowledged messages are never redelivered, and the
producer's flow_id dedup covers the narrow window where a crash occurs between
processing and ack.

A message that keeps failing is dead-lettered rather than retried forever. One
malformed flow must not wedge the pipeline behind it — that would convert a
parsing bug into a total detection outage.
"""
from __future__ import annotations

import json
import logging
import os
import socket
from dataclasses import asdict, dataclass, field
from typing import Any

from ingestion.stream.client import connect

logger = logging.getLogger(__name__)


@dataclass
class ConsumerStats:
    """Counters exposed so nothing is dropped without a number attached."""

    delivered:      int = 0
    acknowledged:   int = 0
    reclaimed:      int = 0
    dead_lettered:  int = 0
    malformed:      int = 0

    def as_dict(self) -> dict[str, int]:
        return asdict(self)


@dataclass(frozen=True)
class StreamFlow:
    """One flow read back off the stream."""

    message_id:       str
    flow_id:          str
    features:         dict[str, float]
    source_ip:        str | None = None
    destination_ip:   str | None = None
    source_port:      int | None = None
    destination_port: int | None = None
    protocol:         int | None = None
    timestamp:        str | None = None
    warnings:         tuple[str, ...] = field(default_factory=tuple)

    def feature_vector(self, order) -> list[float]:
        """Return features in the model's column order."""
        return [self.features[name] for name in order]


class FlowConsumer:
    """Reads flows from the ingest stream as part of a consumer group."""

    def __init__(self, policy, *, client=None, consumer_name: str | None = None) -> None:
        self.policy = policy
        self.client = client if client is not None else connect(policy)
        self.consumer_name = consumer_name or self._default_name(policy)
        self.stats = ConsumerStats()
        self._ensure_group()

    @staticmethod
    def _default_name(policy) -> str:
        """Host and PID, so pending entries name the process that stalled."""
        return f"{policy.consumer_prefix}-{socket.gethostname()}-{os.getpid()}"

    def _ensure_group(self) -> None:
        """Create the consumer group, tolerating an existing one.

        ``mkstream=True`` means a consumer may start before any producer has
        written, which is the normal startup order.
        """
        try:
            self.client.xgroup_create(
                self.policy.stream_key, self.policy.group, id="0", mkstream=True
            )
            logger.info(
                "consumer_group_created",
                extra={"stream": self.policy.stream_key, "group": self.policy.group},
            )
        except Exception as exc:
            if "BUSYGROUP" not in str(exc):
                logger.warning(
                    "consumer_group_create_failed", extra={"error": str(exc)}
                )

    # ── Reading ───────────────────────────────────────────────────────────────

    def read(self, *, count: int | None = None, block_ms: int | None = None) -> list[StreamFlow]:
        """Read a batch of new flows.

        Returns an empty list on timeout, which is a normal idle state rather
        than an error.
        """
        batch = count or self.policy.batch_size
        block = self.policy.block_ms if block_ms is None else block_ms

        try:
            response = self.client.xreadgroup(
                self.policy.group,
                self.consumer_name,
                {self.policy.stream_key: ">"},
                count=batch,
                block=block or None,
            )
        except Exception as exc:
            logger.error("stream_read_failed", extra={"error": str(exc)})
            return []

        return self._decode_response(response)

    def reclaim_stalled(self, *, count: int | None = None) -> list[StreamFlow]:
        """Reclaim messages whose consumer died before acknowledging them.

        This is what makes "lose nothing" true across a crash: without it, a
        killed worker's in-flight flows stay pending forever and are never
        processed by anyone.
        """
        try:
            result = self.client.xautoclaim(
                self.policy.stream_key,
                self.policy.group,
                self.consumer_name,
                min_idle_time=self.policy.claim_idle_ms,
                count=count or self.policy.batch_size,
            )
        except Exception as exc:
            logger.warning("stream_reclaim_failed", extra={"error": str(exc)})
            return []

        # XAUTOCLAIM returns (next_cursor, messages[, deleted]) across versions.
        messages = result[1] if isinstance(result, (list, tuple)) and len(result) > 1 else []
        flows = self._decode_messages(messages)
        if flows:
            self.stats.reclaimed += len(flows)
            logger.info(
                "stream_messages_reclaimed",
                extra={"count": len(flows), "consumer": self.consumer_name},
            )
        return flows

    def read_with_recovery(self, *, count: int | None = None) -> list[StreamFlow]:
        """Reclaim stalled work first, then read new flows.

        Recovery takes priority: a message abandoned by a dead consumer is
        older than anything newly arrived, and processing it late is better
        than processing it never.
        """
        reclaimed = self.reclaim_stalled(count=count)
        if reclaimed:
            return reclaimed
        return self.read(count=count)

    # ── Acknowledging ─────────────────────────────────────────────────────────

    def ack(self, *message_ids: str) -> int:
        """Acknowledge processed messages. Call only after the work is durable."""
        if not message_ids:
            return 0
        try:
            acked = int(
                self.client.xack(self.policy.stream_key, self.policy.group, *message_ids)
            )
        except Exception as exc:
            logger.error("stream_ack_failed", extra={"error": str(exc)})
            return 0
        self.stats.acknowledged += acked
        return acked

    def ack_all(self, flows: list[StreamFlow]) -> int:
        return self.ack(*[flow.message_id for flow in flows])

    # ── Poison messages ───────────────────────────────────────────────────────

    def dead_letter_exhausted(self) -> int:
        """Move messages past the delivery limit to the dead-letter stream.

        A flow that fails every attempt must not block the pipeline behind it.
        It is preserved for inspection rather than dropped — the platform never
        discards evidence silently.
        """
        try:
            pending = self.client.xpending_range(
                self.policy.stream_key,
                self.policy.group,
                min="-",
                max="+",
                count=100,
            )
        except Exception as exc:
            logger.warning("stream_pending_scan_failed", extra={"error": str(exc)})
            return 0

        moved = 0
        for entry in pending or []:
            delivered = int(entry.get("times_delivered", 0))
            if delivered < self.policy.max_delivery_attempts:
                continue
            message_id = entry.get("message_id")
            if not message_id:
                continue
            try:
                records = self.client.xrange(
                    self.policy.stream_key, min=message_id, max=message_id
                )
                payload = records[0][1] if records else {"message_id": message_id}
                payload = dict(payload)
                payload["dead_letter_reason"] = (
                    f"exceeded {self.policy.max_delivery_attempts} delivery attempts"
                )
                payload["original_message_id"] = message_id
                self.client.xadd(self.policy.dead_letter_key, payload)
                self.client.xack(
                    self.policy.stream_key, self.policy.group, message_id
                )
                moved += 1
            except Exception as exc:
                logger.warning(
                    "stream_dead_letter_failed",
                    extra={"message_id": message_id, "error": str(exc)},
                )

        if moved:
            self.stats.dead_lettered += moved
            logger.error(
                "stream_messages_dead_lettered",
                extra={"count": moved, "dead_letter_key": self.policy.dead_letter_key},
            )
        return moved

    def pending_count(self) -> int:
        """Messages delivered but not yet acknowledged."""
        try:
            summary = self.client.xpending(self.policy.stream_key, self.policy.group)
            if isinstance(summary, dict):
                return int(summary.get("pending", 0) or 0)
        except Exception:
            pass
        return 0

    # ── Decoding ──────────────────────────────────────────────────────────────

    def _decode_response(self, response) -> list[StreamFlow]:
        flows: list[StreamFlow] = []
        for _stream_key, messages in response or []:
            flows.extend(self._decode_messages(messages))
        return flows

    def _decode_messages(self, messages) -> list[StreamFlow]:
        flows: list[StreamFlow] = []
        for message_id, fields in messages or []:
            self.stats.delivered += 1
            flow = self._decode(message_id, fields)
            if flow is None:
                # Acknowledge malformed entries: redelivering something that
                # cannot be parsed would retry the same failure forever.
                self.stats.malformed += 1
                self.ack(message_id)
                continue
            flows.append(flow)
        return flows

    def _decode(self, message_id: str, fields: dict[str, Any]) -> StreamFlow | None:
        try:
            features = json.loads(fields["features"])
            if not isinstance(features, dict) or not features:
                raise ValueError("features must be a non-empty object")
            return StreamFlow(
                message_id=message_id,
                flow_id=fields.get("flow_id", ""),
                features={k: float(v) for k, v in features.items()},
                source_ip=fields.get("source_ip") or None,
                destination_ip=fields.get("destination_ip") or None,
                source_port=self._as_int(fields.get("source_port")),
                destination_port=self._as_int(fields.get("destination_port")),
                protocol=self._as_int(fields.get("protocol")),
                timestamp=fields.get("timestamp") or None,
                warnings=tuple(json.loads(fields["warnings"]))
                if fields.get("warnings")
                else (),
            )
        except Exception as exc:
            logger.warning(
                "stream_message_malformed",
                extra={"message_id": message_id, "error": str(exc)},
            )
            return None

    @staticmethod
    def _as_int(value: Any) -> int | None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
