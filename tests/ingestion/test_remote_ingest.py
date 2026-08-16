"""Remote pcap submission — the ingress for sensors that are not this host.

Two properties matter here, and they pull in opposite directions.

It must WORK: a pcap posted by a sensor elsewhere has to reach the same
pipeline, through the same normalizer and stream, as one captured locally.
Anything less and remote mode is a demo feature.

It must not be ABUSABLE: unlike a local capture, this ingress is reachable by
anything holding the API key, and it writes caller-supplied bytes to this
host's disk before parsing them. So the size ceiling, the format check, and the
replay guard are tested as hard as the happy path — a sender that retries a
failed upload must not be able to fabricate a volumetric attack out of one
honest capture.
"""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from ingestion.config import IngestionPolicy
from ingestion.service import (
    UPLOAD_PREFIX,
    IngestionMode,
    IngestionService,
    IngestionServiceError,
)

from tests.ingestion.service_fixtures import FakeBackend, FakeRuntime

fakeredis = pytest.importorskip("fakeredis")


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def policy(tmp_path) -> IngestionPolicy:
    base = IngestionPolicy()
    return replace(
        base,
        capture=replace(
            base.capture, interface="eth0", output_dir=str(tmp_path / "captures")
        ),
        upload=replace(base.upload, work_dir=str(tmp_path / "uploads")),
        worker=replace(base.worker, poll_interval_seconds=1, sweep_interval_seconds=1),
    )


@pytest.fixture
def service(policy, tmp_path) -> IngestionService:
    svc = IngestionService(
        FakeRuntime(),
        policy=policy,
        base_dir=tmp_path,
        redis_client=fakeredis.FakeRedis(decode_responses=True),
    )
    svc.session._backend = FakeBackend()
    return svc


@pytest.fixture
def submitted_pcap(service, tmp_path):
    """Stage a real pcap under the content-addressed name the router would use.

    Built with scapy rather than committed: captures are a record of who talked
    to whom, and `*.pcap` is gitignored for that reason.
    """
    scapy_all = pytest.importorskip("scapy.all")
    IP, TCP, Ether, wrpcap = (
        scapy_all.IP, scapy_all.TCP, scapy_all.Ether, scapy_all.wrpcap
    )

    def build(*, sport: int = 44321, digest: str = "a" * 32) -> Path:
        client_ip, server_ip = "203.0.113.7", "198.51.100.20"
        base_time = 1_700_000_000.0
        packets = []

        def add(pkt, offset):
            pkt.time = base_time + offset
            packets.append(pkt)

        add(Ether() / IP(src=client_ip, dst=server_ip) / TCP(sport=sport, dport=80, flags="S", seq=1000), 0.000)
        add(Ether() / IP(src=server_ip, dst=client_ip) / TCP(sport=80, dport=sport, flags="SA", seq=5000, ack=1001), 0.012)
        add(Ether() / IP(src=client_ip, dst=server_ip) / TCP(sport=sport, dport=80, flags="A", seq=1001, ack=5001), 0.024)
        add(
            Ether() / IP(src=client_ip, dst=server_ip)
            / TCP(sport=sport, dport=80, flags="PA", seq=1001, ack=5001)
            / b"GET /index.html HTTP/1.1\r\nHost: example.test\r\n\r\n",
            0.040,
        )
        add(
            Ether() / IP(src=server_ip, dst=client_ip)
            / TCP(sport=80, dport=sport, flags="PA", seq=5001, ack=1050)
            / b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nhello world!",
            0.095,
        )
        add(Ether() / IP(src=client_ip, dst=server_ip) / TCP(sport=sport, dport=80, flags="FA", seq=1050, ack=5060), 0.150)

        staged = service.upload_dir() / service.stage_upload_name(digest)
        staged.parent.mkdir(parents=True, exist_ok=True)
        wrpcap(str(staged), packets)
        return staged

    return build


# ── Mode selection ────────────────────────────────────────────────────────────


def test_remote_preflight_does_not_require_a_capture_backend(service):
    """A host with no dumpcap can still ingest everything its sensors send."""
    service.session._backend = FakeBackend(available=False)

    result = service.preflight("remote")

    assert result.ready is True
    assert result.mode == "remote"
    assert "capture_backend" not in result.checks
    assert result.checks["upload_policy"] is True


def test_remote_preflight_does_not_require_an_interface(tmp_path):
    """The interface rule exists to stop a wrong tap. Remote mode taps nothing."""
    base = IngestionPolicy()
    no_interface = replace(
        base,
        capture=replace(base.capture, output_dir=str(tmp_path / "c")),
        upload=replace(base.upload, work_dir=str(tmp_path / "u")),
    )
    service = IngestionService(
        FakeRuntime(),
        policy=no_interface,
        base_dir=tmp_path,
        redis_client=fakeredis.FakeRedis(decode_responses=True),
    )
    service.session._backend = FakeBackend(available=False)

    assert service.preflight("capture").ready is False
    assert service.preflight("remote").ready is True


def test_remote_preflight_still_requires_the_stream(policy, tmp_path):
    """Flows with nowhere to go are the one failure this layer must not have."""

    class DeadClient:
        def ping(self):
            raise ConnectionError("connection refused")

    service = IngestionService(
        FakeRuntime(), policy=policy, base_dir=tmp_path, redis_client=DeadClient()
    )
    service.session._backend = FakeBackend()

    result = service.preflight("remote")

    assert result.ready is False
    assert result.checks["stream"] is False


def test_remote_preflight_warns_that_submissions_are_not_witnessed(service):
    """An operator must be told the platform is trusting somebody else's word."""
    warnings = " ".join(service.preflight("remote").warnings)

    assert "sender" in warnings.lower()


def test_an_unknown_mode_is_refused_rather_than_defaulted(service):
    """Falling back to capture would tap a real network on a typo."""
    with pytest.raises(IngestionServiceError, match="Unknown ingestion mode"):
        service.start(mode="remotte")

    assert service.is_running() is False
    assert service.session.backend.starts == 0


def test_remote_mode_starts_the_worker_without_capturing(service):
    service.start(mode="remote")
    try:
        assert service.is_running() is True
        assert service.mode is IngestionMode.REMOTE
        assert service.session.backend.starts == 0, "remote mode must tap nothing"
        assert service.session.is_running() is False
    finally:
        service.stop()


def test_capture_mode_is_still_the_default(service):
    service.start()
    try:
        assert service.mode is IngestionMode.CAPTURE
        assert service.session.backend.starts == 1
    finally:
        service.stop()


def test_an_interface_override_is_refused_in_remote_mode(service):
    """Silently ignoring it would leave an operator believing it was applied."""
    with pytest.raises(IngestionServiceError, match="taps no interface"):
        service.start(mode="remote", interface="eth1")

    assert service.is_running() is False


def test_status_reports_the_mode_and_the_submission_endpoint(service):
    service.start(mode="remote")
    try:
        status = service.status()

        assert status["mode"] == "remote"
        assert status["remote"]["accepting"] is True
        assert status["remote"]["endpoint"] == "/ingestion/pcap"
        assert status["remote"]["max_file_mb"] == service.policy.upload.max_file_mb
    finally:
        service.stop()


# ── Submission ────────────────────────────────────────────────────────────────


def test_a_submitted_pcap_publishes_flows_to_the_stream(service, submitted_pcap):
    """The whole point: a remote pcap joins the same pipeline as a local one."""
    service.start(mode="remote")
    try:
        result = service.ingest_pcap(
            submitted_pcap(), original_name="sensor-a.pcap", source="10.0.0.9"
        )
    finally:
        service.stop()

    assert result["accepted"] is True
    assert result["duplicate"] is False
    assert result["flows_published"] > 0, (
        f"No flows published. extracted={result['flows_extracted']} "
        f"rejected={result['flows_rejected']}. On Windows a cicflowmeter "
        f"failure here is usually the BPF filter - see cicflowmeter/VENDOR.md."
    )
    assert result["source"] == "10.0.0.9"
    assert service.uploads.accepted == 1
    assert service.uploads.flows_published == result["flows_published"]


def test_a_submission_is_deleted_once_processed(service, submitted_pcap):
    """Submitted traffic is as sensitive as captured traffic, and unbounded."""
    service.start(mode="remote")
    staged = submitted_pcap()
    try:
        service.ingest_pcap(staged, original_name="sensor-a.pcap")
    finally:
        service.stop()

    assert not staged.exists()
    assert list(service.upload_dir().glob(f"{UPLOAD_PREFIX}*")) == []


def test_identical_bytes_submitted_twice_are_not_replayed(service, submitted_pcap):
    """A retrying sender must not fabricate a volumetric attack from one capture."""
    service.start(mode="remote")
    try:
        first  = service.ingest_pcap(submitted_pcap(digest="b" * 32))
        second = service.ingest_pcap(submitted_pcap(digest="b" * 32))
    finally:
        service.stop()

    assert first["accepted"] is True and first["flows_published"] > 0
    assert second["duplicate"] is True
    assert second["flows_published"] == 0
    assert service.uploads.duplicates == 1


def test_different_captures_are_both_ingested(service, submitted_pcap):
    """Dedup must key on content, not on the fact that it is an upload."""
    service.start(mode="remote")
    try:
        first  = service.ingest_pcap(submitted_pcap(sport=40001, digest="c" * 32))
        second = service.ingest_pcap(submitted_pcap(sport=40002, digest="d" * 32))
    finally:
        service.stop()

    assert first["accepted"] is True
    assert second["accepted"] is True
    assert service.uploads.duplicates == 0


def test_a_submission_is_refused_when_ingestion_is_not_running(service, tmp_path):
    """Otherwise the sender gets a 'success' for flows no agent will ever read."""
    orphan = service.upload_dir() / f"{UPLOAD_PREFIX}_deadbeef.pcap"
    orphan.parent.mkdir(parents=True, exist_ok=True)
    orphan.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

    with pytest.raises(IngestionServiceError, match="not running"):
        service.ingest_pcap(orphan, original_name="sensor-a.pcap")

    assert not orphan.exists(), "a refused submission must not be left on disk"
    assert service.uploads.rejected == 1


def test_an_unreadable_submission_fails_loudly(service):
    """process_file counts its own failures silently; the sender must be told.

    Also pins that cleanup cannot mask the diagnosis. On Windows a failed
    cicflowmeter run leaves the file handle open, and deleting it in the
    `finally` raised PermissionError — turning "your file is unreadable" into
    an opaque server error, on the one path where the sender most needs to
    know what it did wrong.
    """
    service.start(mode="remote")
    staged = service.upload_dir() / service.stage_upload_name("e" * 32)
    staged.parent.mkdir(parents=True, exist_ok=True)
    # Correct magic bytes, truncated body — passes the transport check and then
    # fails in the flow extractor, which is exactly the case worth pinning.
    staged.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x99" * 16)

    try:
        with pytest.raises(IngestionServiceError, match="could not be processed"):
            service.ingest_pcap(staged, original_name="broken.pcap")
    finally:
        service.stop()

    assert service.uploads.failed == 1


def test_a_submission_the_os_would_not_release_is_swept_later(service):
    """Deferred cleanup is not abandoned cleanup: the sweeper is the backstop."""
    service.policy = replace(
        service.policy, upload=replace(service.policy.upload, retention_seconds=0)
    )
    leftover = service.upload_dir() / service.stage_upload_name("f" * 32)
    leftover.parent.mkdir(parents=True, exist_ok=True)
    leftover.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

    result = service._sweep_uploads()

    assert result.deleted == 1
    assert not leftover.exists()


def test_accepts_submissions_is_false_until_started(service):
    assert service.accepts_submissions() is False
    service.start(mode="remote")
    try:
        assert service.accepts_submissions() is True
    finally:
        service.stop()
    assert service.accepts_submissions() is False


def test_rejections_are_counted_so_a_broken_sensor_is_visible(service):
    """A sender whose files all bounce must not look like a quiet network."""
    service.record_rejected_upload(
        "too large", source="10.0.0.9", filename="huge.pcap"
    )

    uploads = service.status()["uploads"]
    assert uploads["received"] == 1
    assert uploads["rejected"] == 1
    assert uploads["last_source"] == "10.0.0.9"
    assert "too large" in uploads["last_error"]


def test_status_never_reports_credentials_in_remote_mode(policy, tmp_path, monkeypatch):
    import json

    monkeypatch.setenv(policy.stream.password_env, "super-secret-password")
    service = IngestionService(
        FakeRuntime(),
        policy=policy,
        base_dir=tmp_path,
        redis_client=fakeredis.FakeRedis(decode_responses=True),
    )
    service.session._backend = FakeBackend()
    service.start(mode="remote")
    try:
        blob = json.dumps(service.status()) + json.dumps(
            service.preflight("remote").as_dict()
        )
    finally:
        service.stop()

    assert "super-secret-password" not in blob
