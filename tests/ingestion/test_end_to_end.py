"""End-to-end: a real pcap becomes a real detection.

    scapy-built pcap
        -> cicflowmeter          (flow extraction)
        -> FlowNormalizer        (naming + seconds->microseconds)
        -> FlowProducer          (Redis Stream, fakeredis)
        -> FlowConsumer
        -> PipelineBridge        (SecurityEvents, one coordinated run)
        -> CoordinatorAgent -> DetectionAgent -> AnalysisAgent -> DecisionAgent
        -> DetectionResult

WHY THIS TEST EXISTS
--------------------
Every stage of this chain already had thorough unit tests, and the chain was
still broken end to end for months: the model's feature names never matched
what cicflowmeter emits, so all 42 features were zero-filled and a whole
capture scored BENIGN at confidence 1.0. Each component was individually
correct; the *contract between them* was not, and no test crossed the seam.

The assertion that matters is not "a DetectionResult was produced" -- a
zero-filled vector produces one of those too. It is that the flow arrives at
the model with its features actually populated.

The pcap is generated here rather than committed: captures are sensitive (a
record of who talked to whom) and `*.pcap` is gitignored.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from cyber_surakshya.platform.identifiers.correlation import CorrelationContext
from ingestion.bridge.event_builder import EventBuilder
from ingestion.bridge.pipeline_bridge import PipelineBridge
from ingestion.config import StreamPolicy
from ingestion.flows.normalizer import FEATURE_SOURCE_MAP, FlowNormalizer
from ingestion.flows.pcap_processor import PcapProcessor
from ingestion.stream.consumer import FlowConsumer
from ingestion.stream.producer import FlowProducer

fakeredis = pytest.importorskip("fakeredis")
scapy_all = pytest.importorskip("scapy.all")


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def stream_policy() -> StreamPolicy:
    return StreamPolicy(
        stream_key="e2e:flows",
        group="e2e-group",
        dead_letter_key="e2e:flows:dead",
        max_length=1000,
        batch_size=50,
        block_ms=0,
        claim_idle_ms=0,
        max_delivery_attempts=3,
    )


@pytest.fixture
def redis_client():
    return fakeredis.FakeRedis(decode_responses=True)


@pytest.fixture
def capture_file(tmp_path: Path) -> Path:
    """A small synthetic TCP conversation written to a real pcap.

    Timestamps are spread out so inter-arrival-time features are non-zero;
    a capture where every packet shares one timestamp would let a broken
    seconds/microseconds conversion pass unnoticed.
    """
    IP, TCP, Ether, wrpcap = (
        scapy_all.IP, scapy_all.TCP, scapy_all.Ether, scapy_all.wrpcap
    )

    client_ip, server_ip = "203.0.113.7", "198.51.100.20"
    sport, dport = 44321, 80

    packets = []
    base_time = 1_700_000_000.0

    def add(pkt, offset_seconds: float):
        pkt.time = base_time + offset_seconds
        packets.append(pkt)

    # Handshake
    add(Ether() / IP(src=client_ip, dst=server_ip) / TCP(sport=sport, dport=dport, flags="S", seq=1000), 0.000)
    add(Ether() / IP(src=server_ip, dst=client_ip) / TCP(sport=dport, dport=sport, flags="SA", seq=5000, ack=1001), 0.012)
    add(Ether() / IP(src=client_ip, dst=server_ip) / TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=5001), 0.024)

    # Request / response with payload, so packet-length features vary
    add(
        Ether() / IP(src=client_ip, dst=server_ip)
        / TCP(sport=sport, dport=dport, flags="PA", seq=1001, ack=5001)
        / (b"GET /index.html HTTP/1.1\r\nHost: example.test\r\n\r\n"),
        0.040,
    )
    add(
        Ether() / IP(src=server_ip, dst=client_ip)
        / TCP(sport=dport, dport=sport, flags="PA", seq=5001, ack=1050)
        / (b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nhello world!"),
        0.095,
    )

    # Teardown
    add(Ether() / IP(src=client_ip, dst=server_ip) / TCP(sport=sport, dport=dport, flags="FA", seq=1050, ack=5060), 0.150)
    add(Ether() / IP(src=server_ip, dst=client_ip) / TCP(sport=dport, dport=sport, flags="FA", seq=5060, ack=1051), 0.160)

    path = tmp_path / "e2e_capture.pcap"
    wrpcap(str(path), packets)
    return path


# ── The test ──────────────────────────────────────────────────────────────────


def test_pcap_reaches_the_model_with_populated_features(
    capture_file: Path,
    stream_policy: StreamPolicy,
    redis_client,
    tmp_path: Path,
):
    """A captured packet stream must arrive at the model as real numbers."""
    inference = pytest.importorskip("inference")
    try:
        artifacts = inference.IDSArtifacts()
    except inference.ArtifactError as exc:
        pytest.skip(f"IDS artifacts unavailable: {exc}")

    from adapters.detection.ids_adapter import IDSDetectionAdapter
    from agents.analysis.analysis_agent import AnalysisAgent
    from agents.coordinator.coordinator_agent import CoordinatorAgent
    from agents.decision.decision_agent import DecisionAgent
    from agents.decision.deterministic import DeterministicDecisionEngine
    from agents.detection.detection_agent import DetectionAgent
    from ai_engine.deterministic import DeterministicRuleEngine
    from graph.builder import GraphBuilder
    from graph.runtime import GraphRuntime

    # ── capture -> flows -> stream ───────────────────────────────────────────
    normalizer = FlowNormalizer()
    producer   = FlowProducer(stream_policy, client=redis_client)
    processor  = PcapProcessor(
        normalizer, producer, work_dir=tmp_path / "_work"
    )

    published = processor.process_file(capture_file)

    assert processor.stats.files_failed == 0, (
        "cicflowmeter could not read the capture. On Windows this is usually "
        "the BPF filter needing tcpdump - see cicflowmeter/VENDOR.md."
    )
    assert published > 0, (
        f"No flows published from the capture. "
        f"extracted={processor.stats.flows_extracted} "
        f"rejected={processor.stats.flows_rejected}"
    )

    # ── stream -> events -> agents ───────────────────────────────────────────
    consumer = FlowConsumer(stream_policy, client=redis_client)

    adapter = IDSDetectionAdapter(artifacts=artifacts)
    # Detection through decision only. The coordinator must be told which
    # stages exist, or it routes to an unregistered `response` node and the
    # graph refuses to compile. Response execution has its own test suite.
    coordinator = CoordinatorAgent(stages=("detection", "analysis", "decision"))
    builder     = GraphBuilder()
    builder.register_node("detection", DetectionAgent(adapter))
    builder.register_node("analysis",  AnalysisAgent(DeterministicRuleEngine()))
    builder.register_node("decision",  DecisionAgent(DeterministicDecisionEngine()))
    builder.register_coordinator(
        "coordinator", coordinator, coordinator.route,
        routable_targets=coordinator.routable_targets,
    )
    runtime = GraphRuntime(builder=builder)

    bridge    = PipelineBridge(consumer, runtime, event_builder=EventBuilder())
    processed = bridge.run_once()

    assert processed > 0, "The bridge consumed no events from the stream."
    assert bridge.stats.runs_failed == 0
    assert bridge.stats.detections > 0, (
        "Flows reached the pipeline but produced no DetectionResult."
    )


def test_every_model_feature_is_populated_end_to_end(
    capture_file: Path,
    stream_policy: StreamPolicy,
    redis_client,
    tmp_path: Path,
):
    """The regression guard: features must not silently arrive as zeros.

    This is the assertion that would have caught the original bug. A flow can
    travel the whole chain and yield a confident DetectionResult while every
    feature is 0.0 -- which is exactly what happened, for a whole capture.
    """
    normalizer = FlowNormalizer()
    producer   = FlowProducer(stream_policy, client=redis_client)
    processor  = PcapProcessor(normalizer, producer, work_dir=tmp_path / "_work")

    assert processor.process_file(capture_file) > 0

    consumer = FlowConsumer(stream_policy, client=redis_client)
    flows    = consumer.read_with_recovery(count=50)
    assert flows, "No flows on the stream."

    # Real identifiers: SecurityEvent validates these as UUIDs.
    context = CorrelationContext.create()
    events = EventBuilder().build_many(
        flows,
        correlation_id=context.correlation_id,
        trace_id=context.trace_id,
    )
    assert events, "No SecurityEvents built from the flows."

    features = events[0].features

    # 1. Every model feature is present under its CICIDS2017 name.
    assert set(features) == set(normalizer.feature_order), (
        "SecurityEvent features do not match the model's feature contract."
    )

    # 2. The vector is not degenerate. A real TCP conversation must move more
    #    than a couple of features off zero.
    non_zero = {name: value for name, value in features.items() if value != 0.0}
    assert len(non_zero) >= 10, (
        f"Only {len(non_zero)} of {len(features)} features are non-zero: "
        f"{sorted(non_zero)}. A near-empty vector means the naming contract "
        f"between cicflowmeter and the model has broken again."
    )

    # 3. Identity fields survived the round trip.
    assert features["Destination Port"] == 80.0
    assert features["Total Fwd Packets"] > 0

    # 4. Time features are in MICROSECONDS. The capture spans ~0.16 s, so a
    #    correct conversion lands in the 10^4-10^6 range. Without the
    #    seconds->microseconds step this reads ~0.16 and the model receives a
    #    duration a million times too small -- confident, plausible, wrong.
    duration = features["Flow Duration"]
    assert duration > 1000.0, (
        f"Flow Duration is {duration}, which looks like seconds. The "
        f"seconds->microseconds conversion is not being applied."
    )

    # 5. Rate features must NOT have been scaled: per-second in both schemes.
    #    Scaling them is the same bug with the sign flipped.
    assert features["Flow Packets/s"] < 1e6


def test_feature_source_map_covers_the_whole_model_contract():
    """A retrained model with an unmapped feature must fail loudly, not zero-fill."""
    normalizer = FlowNormalizer()
    unmapped = [f for f in normalizer.feature_order if f not in FEATURE_SOURCE_MAP]
    assert unmapped == [], (
        f"{len(unmapped)} model feature(s) have no cicflowmeter source: "
        f"{unmapped}. Extend FEATURE_SOURCE_MAP or the live path zero-fills them."
    )
