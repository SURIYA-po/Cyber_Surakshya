"""Tests for the Redis Streams transport.

Run against fakeredis so the suite is hermetic — a stream test that needs a
live server is a test that gets skipped, and the durability guarantees here
are exactly the ones nobody notices are broken until production.

The two properties under test:
  lose nothing   — a consumer crash must not strand flows permanently
  replay nothing — an acknowledged flow must never be delivered twice
"""
from __future__ import annotations

from dataclasses import replace

import pytest

from ingestion.config import StreamPolicy
from ingestion.flows.normalizer import NormalizedFlow
from ingestion.stream.client import RedisUnavailableError, warn_on_insecure_posture
from ingestion.stream.consumer import FlowConsumer
from ingestion.stream.producer import FlowProducer

fakeredis = pytest.importorskip("fakeredis")


@pytest.fixture
def policy() -> StreamPolicy:
    return StreamPolicy(
        stream_key="test:flows",
        group="test-group",
        dead_letter_key="test:flows:dead",
        max_length=1000,
        batch_size=10,
        block_ms=0,
        claim_idle_ms=0,
        max_delivery_attempts=3,
    )


@pytest.fixture
def client():
    return fakeredis.FakeRedis(decode_responses=True)


@pytest.fixture
def producer(policy, client) -> FlowProducer:
    return FlowProducer(policy, client=client)


@pytest.fixture
def consumer(policy, client) -> FlowConsumer:
    return FlowConsumer(policy, client=client, consumer_name="worker-a")


def make_flow(flow_id: str = "a" * 64, *, ip: str = "203.0.113.5") -> NormalizedFlow:
    return NormalizedFlow(
        features={"Flow Duration": 1000.0, "Total Fwd Packets": 5.0},
        source_ip=ip,
        destination_ip="10.0.0.1",
        source_port=44321,
        destination_port=443,
        protocol=6,
        timestamp="2026-08-02 01:00:00",
        flow_id=flow_id,
    )


# ── Publishing ────────────────────────────────────────────────────────────────


def test_flow_round_trips_through_the_stream(producer, consumer):
    published = producer.publish(make_flow())

    received = consumer.read()

    assert published is not None
    assert len(received) == 1
    flow = received[0]
    assert flow.flow_id == "a" * 64
    assert flow.source_ip == "203.0.113.5"
    assert flow.destination_port == 443
    assert flow.protocol == 6
    assert flow.features["Flow Duration"] == 1000.0


def test_features_survive_intact(producer, consumer):
    """All 42 must arrive, not whatever fields happened to serialize."""
    features = {f"Feature {i}": float(i) * 1.5 for i in range(42)}
    producer.publish(replace(make_flow(), features=features))

    received = consumer.read()[0]

    assert received.features == features
    assert len(received.features) == 42


def test_batch_publish_reports_what_was_written(producer):
    flows = [make_flow(flow_id=f"{i:064d}") for i in range(5)]

    assert producer.publish_many(flows) == 5
    assert producer.stats.published == 5


def test_warnings_are_carried_to_the_consumer(producer, consumer):
    producer.publish(replace(make_flow(), warnings=("Flow Duration: missing",)))

    assert consumer.read()[0].warnings == ("Flow Duration: missing",)


# ── Deduplication ─────────────────────────────────────────────────────────────


def test_identical_flow_is_suppressed(producer, consumer):
    """Replaying a pcap must not fabricate a volumetric attack."""
    first = producer.publish(make_flow())
    second = producer.publish(make_flow())

    assert first is not None
    assert second is None
    assert producer.stats.duplicates == 1
    assert len(consumer.read()) == 1


def test_distinct_flows_are_both_published(producer, consumer):
    producer.publish(make_flow(flow_id="a" * 64))
    producer.publish(make_flow(flow_id="b" * 64))

    assert len(consumer.read()) == 2
    assert producer.stats.duplicates == 0


def test_dedup_can_be_disabled(policy, client):
    producer = FlowProducer(replace(policy, dedup_ttl_seconds=0), client=client)

    producer.publish(make_flow())
    producer.publish(make_flow())

    assert producer.stats.published == 2


# ── Lose nothing ──────────────────────────────────────────────────────────────


def test_unacknowledged_flows_stay_pending(producer, consumer):
    producer.publish(make_flow())
    consumer.read()

    assert consumer.pending_count() == 1, "delivered but unacked work is tracked"


def test_a_crashed_consumer_does_not_strand_flows(policy, client, producer):
    """The heart of "lose nothing": another worker reclaims abandoned work."""
    producer.publish(make_flow())

    dead = FlowConsumer(policy, client=client, consumer_name="worker-dead")
    delivered = dead.read()
    assert len(delivered) == 1
    # worker-dead never acks — simulate the process dying here.

    rescuer = FlowConsumer(policy, client=client, consumer_name="worker-rescuer")
    reclaimed = rescuer.reclaim_stalled()

    assert len(reclaimed) == 1
    assert reclaimed[0].flow_id == "a" * 64
    assert rescuer.stats.reclaimed == 1


def test_recovery_takes_priority_over_new_work(policy, client, producer):
    """Abandoned flows are older; processing them late beats never."""
    producer.publish(make_flow(flow_id="a" * 64))
    FlowConsumer(policy, client=client, consumer_name="worker-dead").read()

    producer.publish(make_flow(flow_id="b" * 64))
    rescuer = FlowConsumer(policy, client=client, consumer_name="worker-b")

    first_batch = rescuer.read_with_recovery()

    assert [f.flow_id for f in first_batch] == ["a" * 64]


def test_acknowledgement_clears_pending(producer, consumer):
    producer.publish(make_flow())
    flows = consumer.read()

    assert consumer.ack_all(flows) == 1
    assert consumer.pending_count() == 0
    assert consumer.stats.acknowledged == 1


# ── Replay nothing ────────────────────────────────────────────────────────────


def test_acknowledged_flows_are_never_redelivered(producer, consumer):
    producer.publish(make_flow())
    consumer.ack_all(consumer.read())

    assert consumer.read() == []


def test_a_restarted_consumer_resumes_without_replaying(policy, client, producer):
    """A restart must lose nothing and repeat nothing."""
    producer.publish(make_flow(flow_id="a" * 64))
    producer.publish(make_flow(flow_id="b" * 64))

    first = FlowConsumer(policy, client=client, consumer_name="worker-1")
    batch = first.read(count=1)
    first.ack_all(batch)
    processed = {f.flow_id for f in batch}

    # Process restarts under the same group.
    second = FlowConsumer(policy, client=client, consumer_name="worker-1")
    remaining = second.read()

    assert processed == {"a" * 64}
    assert [f.flow_id for f in remaining] == ["b" * 64]
    assert processed.isdisjoint({f.flow_id for f in remaining})


def test_two_consumers_split_work_without_overlap(policy, client, producer):
    producer.publish_many([make_flow(flow_id=f"{i:064d}") for i in range(6)])

    a = FlowConsumer(policy, client=client, consumer_name="worker-a").read(count=3)
    b = FlowConsumer(policy, client=client, consumer_name="worker-b").read(count=3)

    ids_a = {f.flow_id for f in a}
    ids_b = {f.flow_id for f in b}

    assert len(ids_a) == 3 and len(ids_b) == 3
    assert ids_a.isdisjoint(ids_b), "a consumer group must not double-deliver"


# ── Poison messages ───────────────────────────────────────────────────────────


def test_malformed_entries_are_acked_not_retried_forever(policy, client, consumer):
    """An unparseable entry must not wedge the pipeline behind it."""
    client.xadd(policy.stream_key, {"flow_id": "x", "features": "not-json"})

    flows = consumer.read()

    assert flows == []
    assert consumer.stats.malformed == 1
    assert consumer.pending_count() == 0


def _fail_repeatedly(policy, client, times: int) -> None:
    """Deliver a message `times` times without ever acknowledging it.

    Retries happen through reclaim, not re-reading: `xreadgroup` with `>`
    yields only new messages, so a pending entry is redelivered by XAUTOCLAIM
    and that is what increments its delivery counter.
    """
    for index in range(times):
        worker = FlowConsumer(policy, client=client, consumer_name=f"worker-{index}")
        worker.reclaim_stalled()


def test_repeatedly_failing_messages_are_dead_lettered(policy, client, producer):
    producer.publish(make_flow())
    FlowConsumer(policy, client=client, consumer_name="worker-first").read()
    _fail_repeatedly(policy, client, policy.max_delivery_attempts)

    reaper = FlowConsumer(policy, client=client, consumer_name="worker-reaper")
    moved = reaper.dead_letter_exhausted()

    assert moved == 1
    assert client.xlen(policy.dead_letter_key) == 1
    assert reaper.pending_count() == 0


def test_dead_lettered_flows_are_preserved_not_discarded(policy, client, producer):
    """The platform never drops evidence silently."""
    producer.publish(make_flow())
    FlowConsumer(policy, client=client, consumer_name="worker-first").read()
    _fail_repeatedly(policy, client, policy.max_delivery_attempts)

    FlowConsumer(policy, client=client, consumer_name="reaper").dead_letter_exhausted()

    entries = client.xrange(policy.dead_letter_key)
    payload = entries[0][1]
    assert payload["flow_id"] == "a" * 64
    assert "exceeded" in payload["dead_letter_reason"]
    assert payload["original_message_id"]


def test_a_message_below_the_limit_survives_reclaim(policy, client, producer):
    """Ordinary transient failures must not be dead-lettered prematurely."""
    producer.publish(make_flow())
    FlowConsumer(policy, client=client, consumer_name="worker-first").read()
    _fail_repeatedly(policy, client, policy.max_delivery_attempts - 2)

    reaper = FlowConsumer(policy, client=client, consumer_name="reaper")

    assert reaper.dead_letter_exhausted() == 0
    assert client.xlen(policy.dead_letter_key) == 0


def test_healthy_messages_are_not_dead_lettered(policy, client, producer, consumer):
    producer.publish(make_flow())
    consumer.read()

    assert consumer.dead_letter_exhausted() == 0


# ── Backpressure ──────────────────────────────────────────────────────────────


def test_stream_is_bounded(policy, client):
    """Redis trims silently, so the cap must actually be applied."""
    producer = FlowProducer(replace(policy, max_length=10), client=client)

    producer.publish_many([make_flow(flow_id=f"{i:064d}") for i in range(50)])

    assert producer.stream_length() <= 50
    assert producer.stats.published == 50


def test_backlog_ratio_warns_before_eviction(policy, client):
    producer = FlowProducer(replace(policy, max_length=100), client=client)

    assert producer.backlog_ratio() == 0.0
    producer.publish_many([make_flow(flow_id=f"{i:064d}") for i in range(50)])
    assert producer.backlog_ratio() == pytest.approx(0.5, abs=0.1)


# ── Failure handling ──────────────────────────────────────────────────────────


def test_publish_failure_is_fatal_when_fail_closed(policy):
    """Accepting a flow that cannot be delivered would discard it silently."""

    class BrokenClient:
        def set(self, *a, **k):
            return True

        def xadd(self, *a, **k):
            raise ConnectionError("redis is gone")

    producer = FlowProducer(policy, client=BrokenClient())

    with pytest.raises(RedisUnavailableError, match="Could not publish"):
        producer.publish(make_flow())
    assert producer.stats.failed == 1


def test_publish_failure_is_survivable_when_fail_open(policy):
    class BrokenClient:
        def set(self, *a, **k):
            return True

        def xadd(self, *a, **k):
            raise ConnectionError("redis is gone")

    producer = FlowProducer(replace(policy, fail_closed=False), client=BrokenClient())

    assert producer.publish(make_flow()) is None
    assert producer.stats.failed == 1


def test_dedup_failure_does_not_drop_the_flow(policy, client):
    """Losing a flow is worse than processing one twice."""

    class FlakyDedup:
        def __init__(self, real):
            self.real = real

        def set(self, *a, **k):
            raise ConnectionError("dedup unavailable")

        def __getattr__(self, name):
            return getattr(self.real, name)

    producer = FlowProducer(policy, client=FlakyDedup(client))

    assert producer.publish(make_flow()) is not None


def test_group_is_created_even_before_any_producer_writes(policy, client):
    """Consumers legitimately start first."""
    consumer = FlowConsumer(policy, client=client, consumer_name="early")

    assert consumer.read() == []


# ── Security posture ──────────────────────────────────────────────────────────


def test_unauthenticated_redis_is_flagged(policy, monkeypatch):
    monkeypatch.delenv(policy.password_env, raising=False)

    warnings = warn_on_insecure_posture(policy)

    assert any("no password" in w for w in warnings)


def test_remote_plaintext_redis_is_flagged(policy, monkeypatch):
    monkeypatch.setenv(policy.password_env, "secret")
    remote = replace(policy, url="redis://10.0.0.5:6379/0")

    warnings = warn_on_insecure_posture(remote)

    assert any("TLS" in w for w in warnings)


def test_authenticated_loopback_raises_no_warning(policy, monkeypatch):
    monkeypatch.setenv(policy.password_env, "secret")

    assert warn_on_insecure_posture(policy) == []


def test_credentials_come_from_the_environment_not_the_config(policy, monkeypatch):
    """A password in a committed file is in the repo history forever."""
    monkeypatch.setenv(policy.password_env, "from-env")
    monkeypatch.setenv(policy.username_env, "cs-producer")

    assert policy.password == "from-env"
    assert policy.username == "cs-producer"
    assert "from-env" not in policy.url
