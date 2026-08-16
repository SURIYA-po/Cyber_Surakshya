"""Tests for the ingestion → agent pipeline bridge.

The headline case is the timezone conversion in EventBuilder. cicflowmeter
stamps flows with `datetime.fromtimestamp()` — local, naive — and the platform
stores UTC. Reading that naive value as UTC does not raise; it makes
`observed_at` wrong by the host's UTC offset, `time_to_detect()` negative, and
MTTD permanently unmeasurable while looking like missing data.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from cyber_surakshya.platform.enums.event_type import EventType
from cyber_surakshya.platform.enums.severity import Severity
from cyber_surakshya.platform.identifiers.correlation import CorrelationContext
from cyber_surakshya.platform.schemas.security_event import SecurityEvent
from cyber_surakshya.platform.state import PlatformStateModel, create_initial_state
from ingestion.bridge.event_builder import EventBuilder, _to_utc
from ingestion.bridge.pipeline_bridge import PIPELINE_STAGES, PipelineBridge
from ingestion.flows.normalizer import NormalizedFlow
from ingestion.flows.pcap_processor import PcapProcessor

CTX = CorrelationContext.create()


def make_flow(**overrides) -> NormalizedFlow:
    defaults = dict(
        features={"Flow Duration": 1000.0, "Total Fwd Packets": 5.0},
        source_ip="203.0.113.7",
        destination_ip="10.0.0.1",
        source_port=44321,
        destination_port=443,
        protocol=6,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        flow_id="a" * 64,
    )
    defaults.update(overrides)
    return NormalizedFlow(**defaults)


def build(flow) -> SecurityEvent:
    return EventBuilder().build(
        flow, correlation_id=CTX.correlation_id, trace_id=CTX.trace_id
    )


# ── The timezone trap ─────────────────────────────────────────────────────────


def test_naive_flow_timestamp_is_read_as_local_not_utc():
    """The bug this module exists to prevent.

    `datetime.fromtimestamp()` produces local wall-clock time. Tagging it UTC
    shifts observed_at by the host offset — on UTC+5:45 that is ~6 hours into
    the future.
    """
    local_naive = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    converted = _to_utc(local_naive)
    naive_as_utc = datetime.strptime(local_naive, "%Y-%m-%d %H:%M:%S").replace(
        tzinfo=timezone.utc
    )
    now = datetime.now(timezone.utc)

    assert converted.tzinfo is timezone.utc
    assert abs((now - converted).total_seconds()) < 60, "must be ~now in UTC"
    # On a UTC-offset host the naive reading is measurably wrong.
    offset = abs((naive_as_utc - converted).total_seconds())
    if offset:
        assert offset > 60, "the two readings genuinely differ on this host"


def test_time_to_detect_is_positive():
    """Negative durations are discarded, so a wrong zone hides MTTD entirely."""
    event = build(make_flow())

    elapsed = (datetime.now(timezone.utc) - event.observed_at).total_seconds()

    assert elapsed >= 0, "a negative time-to-detect is silently dropped by metrics"
    assert elapsed < 120


def test_observed_at_never_exceeds_ingested_at():
    """Clock skew must be clamped, not propagated into the metrics."""
    future = (datetime.now() + timedelta(hours=3)).strftime("%Y-%m-%d %H:%M:%S")

    event = build(make_flow(timestamp=future))

    assert event.observed_at <= event.ingested_at


def test_missing_timestamp_falls_back_to_ingest_time():
    event = build(make_flow(timestamp=None))

    assert event.observed_at == event.ingested_at


def test_unparseable_timestamp_falls_back_rather_than_raising():
    event = build(make_flow(timestamp="not-a-timestamp"))

    assert event.observed_at == event.ingested_at


def test_iso_timestamps_are_accepted():
    aware = "2026-08-01T12:00:00+00:00"

    converted = _to_utc(aware)

    assert converted == datetime(2026, 8, 1, 12, 0, tzinfo=timezone.utc)


def test_already_aware_datetimes_are_preserved():
    aware = datetime(2026, 8, 1, 12, 0, tzinfo=timezone.utc)

    assert _to_utc(aware) == aware


# ── Event construction ────────────────────────────────────────────────────────


def test_flow_becomes_a_valid_security_event():
    event = build(make_flow())

    assert event.event_type is EventType.NETWORK_FLOW
    assert event.correlation_id == CTX.correlation_id
    assert event.network.source_ip == "203.0.113.7"
    assert event.network.destination_port == 443
    assert event.features == {"Flow Duration": 1000.0, "Total Fwd Packets": 5.0}


def test_severity_and_risk_are_left_for_the_detection_agent():
    """Ingestion observes; it does not judge."""
    event = build(make_flow())

    assert event.severity is Severity.INFO
    assert event.risk_score.value == 0.0


def test_protocol_number_becomes_a_name():
    """NetworkEndpoint.protocol is a string; flows carry the IANA number."""
    assert build(make_flow(protocol=6)).network.protocol == "TCP"
    assert build(make_flow(protocol=17)).network.protocol == "UDP"
    assert build(make_flow(protocol=1)).network.protocol == "ICMP"


def test_unknown_protocol_number_is_preserved_not_dropped():
    assert build(make_flow(protocol=253)).network.protocol == "253"


def test_missing_protocol_is_allowed():
    assert build(make_flow(protocol=None)).network.protocol is None


def test_flow_id_is_carried_for_traceability():
    event = build(make_flow())

    assert event.labels["flow_id"] == "a" * 64
    assert event.labels["ingestion"] == "network_capture"


def test_batch_skips_unbuildable_flows_without_aborting():
    good = make_flow()
    bad = make_flow(source_ip="not-an-ip-address")

    events = EventBuilder().build_many(
        [good, bad, good], correlation_id=CTX.correlation_id, trace_id=CTX.trace_id
    )

    assert len(events) == 2, "one invalid flow must not lose the batch"


# ── Bridge ────────────────────────────────────────────────────────────────────


class FakeConsumer:
    """Consumer double that records acknowledgement behaviour."""

    def __init__(self, batches):
        self.batches = list(batches)
        self.acked = []
        self.consumer_name = "fake"

        class _Stats:
            def as_dict(self):
                return {}

        self.stats = _Stats()

    def read_with_recovery(self, count=None):
        return self.batches.pop(0) if self.batches else []

    def ack_all(self, flows):
        self.acked.extend(flows)
        return len(flows)

    def pending_count(self):
        return 0


class FakeRuntime:
    """Runtime double returning a completed state."""

    def __init__(self, *, fail: bool = False, pending: int = 0):
        self.fail = fail
        self.pending = pending
        self.runs = 0
        self.last_state = None

    def execute(self, state):
        self.runs += 1
        self.last_state = state
        if self.fail:
            raise RuntimeError("graph exploded")
        model = PlatformStateModel.model_validate(state.model_dump(mode="json"))
        model.metadata = {
            "coordinator_agent": {
                "status": "completed",
                "pending_total": self.pending,
                "stalled_stages": [],
            }
        }
        return model


class StreamFlowStub:
    def __init__(self, message_id, flow):
        self.message_id = message_id
        for attr in (
            "features", "source_ip", "destination_ip", "source_port",
            "destination_port", "protocol", "timestamp", "flow_id",
        ):
            setattr(self, attr, getattr(flow, attr))


def stream_flows(count: int):
    return [StreamFlowStub(f"{i}-0", make_flow(flow_id=f"{i:064d}")) for i in range(count)]


def test_batch_runs_through_the_pipeline_and_acks():
    consumer = FakeConsumer([stream_flows(3)])
    runtime = FakeRuntime()
    bridge = PipelineBridge(consumer, runtime)

    processed = bridge.run_once()

    assert processed == 3
    assert runtime.runs == 1
    assert len(consumer.acked) == 3
    assert bridge.stats.batches_run == 1


def test_all_events_share_one_correlation_id():
    """One batch is one coordinated run — that is the coordinator's shape."""
    consumer = FakeConsumer([stream_flows(4)])
    runtime = FakeRuntime()

    PipelineBridge(consumer, runtime).run_once()

    ids = {e.correlation_id for e in runtime.last_state.security_events}
    assert len(ids) == 1
    assert len(runtime.last_state.security_events) == 4


def test_idle_stream_is_not_an_error():
    bridge = PipelineBridge(FakeConsumer([]), FakeRuntime())

    assert bridge.run_once() == 0
    assert bridge.stats.runs_failed == 0


def test_failed_run_leaves_flows_unacknowledged_for_retry():
    """Unacked work is reclaimed by another consumer — that is "lose nothing"."""
    consumer = FakeConsumer([stream_flows(3)])
    bridge = PipelineBridge(consumer, FakeRuntime(fail=True))

    processed = bridge.run_once()

    assert processed == 0
    assert consumer.acked == [], "a failed batch must stay pending"
    assert bridge.stats.runs_failed == 1


def test_unbuildable_batch_is_acked_after_being_counted():
    """Nothing buildable must not redeliver forever, but the loss is recorded."""
    broken = [StreamFlowStub("1-0", make_flow(source_ip="nope"))]
    consumer = FakeConsumer([broken])
    bridge = PipelineBridge(consumer, FakeRuntime())

    assert bridge.run_once() == 0
    assert len(consumer.acked) == 1
    assert bridge.stats.events_dropped == 1


def test_batch_is_capped_to_the_coordinator_budget():
    """N events cost N × 4 dispatches; overrunning strands the remainder."""
    bridge = PipelineBridge(
        FakeConsumer([]), FakeRuntime(), max_events_per_run=50, coordinator_budget=100
    )

    assert bridge.max_events_per_run == 100 // PIPELINE_STAGES


def test_generous_budget_leaves_the_requested_batch_alone():
    bridge = PipelineBridge(
        FakeConsumer([]), FakeRuntime(), max_events_per_run=20, coordinator_budget=1000
    )

    assert bridge.max_events_per_run == 20


def test_drain_stops_when_the_stream_is_idle():
    consumer = FakeConsumer([stream_flows(2), stream_flows(2), []])
    runtime = FakeRuntime()
    bridge = PipelineBridge(consumer, runtime)

    assert bridge.drain(max_batches=10) == 4
    assert runtime.runs == 2


def test_drain_respects_the_batch_limit():
    consumer = FakeConsumer([stream_flows(1) for _ in range(10)])
    runtime = FakeRuntime()

    PipelineBridge(consumer, runtime).drain(max_batches=3)

    assert runtime.runs == 3


def test_status_reports_counters():
    consumer = FakeConsumer([stream_flows(2)])
    bridge = PipelineBridge(consumer, FakeRuntime())
    bridge.run_once()

    status = bridge.status()

    assert status["bridge"]["events_built"] == 2
    assert status["bridge"]["flows_acked"] == 2
    assert "max_events_per_run" in status


# ── Pcap processor ────────────────────────────────────────────────────────────


class FakeProducer:
    def __init__(self):
        self.published = []

    def publish_many(self, flows):
        self.published.extend(flows)
        return len(flows)


class FakeNormalizer:
    def __init__(self):
        class _Stats:
            rejected = 0

        self.stats = _Stats()

    def validate_source_columns(self, columns):
        return None

    def normalize_frame(self, frame):
        return [make_flow(flow_id=f"{i:064d}") for i in range(len(frame))]


def test_processed_files_are_not_reprocessed(tmp_path, monkeypatch):
    """Reprocessing a capture would fabricate duplicate traffic."""
    import pandas as pd

    pcap = tmp_path / "cs_00001.pcap"
    pcap.write_bytes(b"\0" * 10)

    producer = FakeProducer()
    processor = PcapProcessor(FakeNormalizer(), producer, work_dir=tmp_path)
    monkeypatch.setattr(
        processor, "_extract_flows", lambda path: pd.DataFrame({"a": [1, 2, 3]})
    )

    first = processor.process_ready([pcap])
    second = processor.process_ready([pcap])

    assert first == 3
    assert second == 0
    assert processor.stats.files_skipped == 1


def test_empty_capture_is_marked_done_not_retried(tmp_path, monkeypatch):
    """A quiet interface is normal, not a failure to retry forever."""
    pcap = tmp_path / "cs_00001.pcap"
    pcap.write_bytes(b"\0")

    processor = PcapProcessor(FakeNormalizer(), FakeProducer(), work_dir=tmp_path)
    monkeypatch.setattr(processor, "_extract_flows", lambda path: None)

    assert processor.process_ready([pcap]) == 0
    assert processor.stats.files_processed == 1
    assert processor.already_processed(pcap) is True


def test_extraction_failure_is_counted_and_not_marked_done(tmp_path, monkeypatch):
    pcap = tmp_path / "cs_00001.pcap"
    pcap.write_bytes(b"\0")

    processor = PcapProcessor(FakeNormalizer(), FakeProducer(), work_dir=tmp_path)

    def boom(path):
        raise OSError("corrupt pcap")

    monkeypatch.setattr(processor, "_extract_flows", boom)

    assert processor.process_ready([pcap]) == 0
    assert processor.stats.files_failed == 1
    assert processor.already_processed(pcap) is False, "a failure must be retryable"


def test_schema_mismatch_rejects_the_file(tmp_path, monkeypatch):
    import pandas as pd

    from ingestion.exceptions import FeatureContractError

    pcap = tmp_path / "cs_00001.pcap"
    pcap.write_bytes(b"\0")

    class StrictNormalizer(FakeNormalizer):
        def validate_source_columns(self, columns):
            raise FeatureContractError("missing flow_duration")

    processor = PcapProcessor(StrictNormalizer(), FakeProducer(), work_dir=tmp_path)
    monkeypatch.setattr(
        processor, "_extract_flows", lambda path: pd.DataFrame({"a": [1]})
    )

    assert processor.process_ready([pcap]) == 0
    assert processor.stats.files_failed == 1


def test_processed_state_survives_via_the_state_client(tmp_path, monkeypatch):
    """A restart must neither reprocess nor skip."""
    import pandas as pd

    fakeredis = pytest.importorskip("fakeredis")
    client = fakeredis.FakeRedis(decode_responses=True)
    pcap = tmp_path / "cs_00001.pcap"
    pcap.write_bytes(b"\0")

    first = PcapProcessor(
        FakeNormalizer(), FakeProducer(), state_client=client, work_dir=tmp_path
    )
    monkeypatch.setattr(first, "_extract_flows", lambda path: pd.DataFrame({"a": [1]}))
    first.process_ready([pcap])

    # New process, same Redis.
    second = PcapProcessor(
        FakeNormalizer(), FakeProducer(), state_client=client, work_dir=tmp_path
    )

    assert second.already_processed(pcap) is True
