"""Tests for capture session lifecycle, backend selection, and retention."""
from __future__ import annotations

import time
from dataclasses import replace
from pathlib import Path

import pytest

from ingestion.capture.backends.base import (
    CaptureBackend,
    CaptureBackendError,
    CaptureHandle,
    InterfaceInfo,
)
from ingestion.capture.backends.local_dumpcap import LocalDumpcapBackend
from ingestion.capture.retention import list_capture_files, newest_file, sweep
from ingestion.capture.session import CaptureSession, CaptureSessionError
from ingestion.config import IngestionPolicy


class FakeBackend(CaptureBackend):
    """A backend that records calls instead of touching the network."""

    backend_name = "fake"

    def __init__(self, *, available: bool = True, fail_start: str | None = None) -> None:
        self.available   = available
        self.fail_start  = fail_start
        self.running     = False
        self.start_calls = 0
        self.stop_calls  = 0

    def is_available(self) -> bool:
        return self.available

    def unavailable_reason(self) -> str:
        return "fake backend disabled for this test"

    def list_interfaces(self):
        return [InterfaceInfo(identifier="eth0", display_name="eth0", index=1)]

    def start(self, policy, output_dir: Path) -> CaptureHandle:
        self.start_calls += 1
        if self.fail_start:
            raise CaptureBackendError(self.fail_start)
        output_dir.mkdir(parents=True, exist_ok=True)
        self.running = True
        return CaptureHandle(
            backend=self.backend_name,
            identifier="1234",
            interface=policy.interface,
            output_dir=output_dir,
            file_prefix=policy.file_prefix,
        )

    def stop(self, handle, *, timeout: float = 10.0) -> bool:
        self.stop_calls += 1
        was = self.running
        self.running = False
        return was

    def is_running(self, handle) -> bool:
        return self.running


@pytest.fixture
def policy(tmp_path) -> IngestionPolicy:
    base = IngestionPolicy()
    return replace(
        base,
        capture=replace(
            base.capture, interface="eth0", output_dir=str(tmp_path / "captures")
        ),
    )


@pytest.fixture
def session(policy, tmp_path) -> CaptureSession:
    return CaptureSession(policy, backend=FakeBackend(), base_dir=tmp_path)


def _touch_pcap(directory: Path, name: str, *, size: int = 100, age: float = 0.0):
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_bytes(b"\0" * size)
    if age:
        stamp = time.time() - age
        import os

        os.utime(path, (stamp, stamp))
    return path


# ── Lifecycle ─────────────────────────────────────────────────────────────────


def test_start_then_stop(session):
    status = session.start()

    assert status.running is True
    assert status.interface == "eth0"
    assert session.is_running() is True

    stopped = session.stop()

    assert stopped.running is False
    assert session.is_running() is False


def test_double_start_is_refused(session):
    session.start()

    with pytest.raises(CaptureSessionError, match="already running"):
        session.start()


def test_stop_is_idempotent(session):
    assert session.stop().running is False
    session.start()
    session.stop()
    assert session.stop().running is False


def test_unavailable_backend_refuses_to_start(policy, tmp_path):
    session = CaptureSession(
        policy, backend=FakeBackend(available=False), base_dir=tmp_path
    )

    with pytest.raises(CaptureSessionError, match="disabled for this test"):
        session.start()


def test_backend_failure_is_reported_in_status(policy, tmp_path):
    backend = FakeBackend(fail_start="no such interface")
    session = CaptureSession(policy, backend=backend, base_dir=tmp_path)

    with pytest.raises(CaptureSessionError, match="no such interface"):
        session.start()

    assert session.status().last_error == "no such interface"


def test_missing_interface_refuses_before_touching_the_backend(tmp_path):
    base = IngestionPolicy()
    unset = replace(
        base, capture=replace(base.capture, output_dir=str(tmp_path / "c"))
    )
    backend = FakeBackend()
    session = CaptureSession(unset, backend=backend, base_dir=tmp_path)

    with pytest.raises(CaptureSessionError, match="will not guess"):
        session.start()

    assert backend.start_calls == 0, "policy must be validated before starting"


# ── Status ────────────────────────────────────────────────────────────────────


def test_status_reports_the_retention_window(session):
    status = session.status()

    assert status.rotate_seconds == 60
    assert status.retain_files == 120
    assert status.retention_seconds == 7200


def test_status_counts_files_and_excludes_the_active_one(session, tmp_path):
    captures = tmp_path / "captures"
    for index in range(3):
        _touch_pcap(captures, f"cs_0000{index}.pcap", age=10 - index)

    status = session.status()

    assert status.file_count == 3
    assert status.ready_file_count == 2, "the newest file is still being written"
    assert status.active_file is not None


def test_status_serializes_for_the_api(session):
    payload = session.status().to_dict()

    assert payload["running"] is False
    assert payload["snaplen"] == 96
    assert "retention_seconds" in payload
    assert "total_mb" in payload


# ── Ready files ───────────────────────────────────────────────────────────────


def test_ready_files_never_includes_the_file_being_written(session, tmp_path):
    captures = tmp_path / "captures"
    oldest = _touch_pcap(captures, "cs_00001.pcap", age=30)
    middle = _touch_pcap(captures, "cs_00002.pcap", age=20)
    newest = _touch_pcap(captures, "cs_00003.pcap", age=1)

    ready = session.ready_files()

    assert ready == [oldest, middle]
    assert newest not in ready


def test_a_single_file_is_never_ready(session, tmp_path):
    _touch_pcap(tmp_path / "captures", "cs_00001.pcap")

    assert session.ready_files() == []


# ── Retention ─────────────────────────────────────────────────────────────────


def test_sweep_deletes_expired_files_but_protects_the_active_one(tmp_path):
    captures = tmp_path / "caps"
    _touch_pcap(captures, "cs_00001.pcap", age=9999)
    _touch_pcap(captures, "cs_00002.pcap", age=9998)
    _touch_pcap(captures, "cs_00003.pcap", age=1)

    result = sweep(captures, prefix="cs", max_age_seconds=60, keep_newest=True)

    assert result.deleted == 2
    assert result.remaining == 1
    assert newest_file(captures, "cs") is not None


def test_sweep_enforces_a_total_size_ceiling(tmp_path):
    """A restarted dumpcap leaves the previous ring behind; -b files cannot see it."""
    captures = tmp_path / "caps"
    for index in range(5):
        _touch_pcap(captures, f"cs_0000{index}.pcap", size=1000, age=100 - index)

    result = sweep(captures, prefix="cs", max_total_bytes=2500, keep_newest=True)

    assert result.remaining_bytes <= 2500
    assert result.deleted >= 2


def test_sweep_ignores_unrelated_files(tmp_path):
    captures = tmp_path / "caps"
    _touch_pcap(captures, "cs_00001.pcap", age=9999)
    (captures / "notes.txt").write_bytes(b"keep me")
    _touch_pcap(captures, "other_00001.pcap", age=9999)

    sweep(captures, prefix="cs", max_age_seconds=1, keep_newest=False)

    assert (captures / "notes.txt").exists()
    assert (captures / "other_00001.pcap").exists()


def test_sweep_on_empty_directory_is_harmless(tmp_path):
    result = sweep(tmp_path / "nothing", prefix="cs", max_age_seconds=1)

    assert result.deleted == 0
    assert result.scanned == 0


def test_list_capture_files_is_oldest_first(tmp_path):
    captures = tmp_path / "caps"
    _touch_pcap(captures, "cs_b.pcap", age=10)
    _touch_pcap(captures, "cs_a.pcap", age=100)

    names = [f.path.name for f in list_capture_files(captures, "cs")]

    assert names == ["cs_a.pcap", "cs_b.pcap"]


# ── Backend selection ─────────────────────────────────────────────────────────


def test_docker_backend_is_rejected_on_docker_desktop(policy, tmp_path):
    """--net=host on Docker Desktop joins the VM's namespace, not the host's.

    A capture started there succeeds against the wrong network while looking
    perfectly healthy, so the session must substitute rather than proceed.
    """
    from ingestion.capture.backends.docker_dumpcap import DockerDumpcapBackend

    backend = DockerDumpcapBackend(policy.docker, docker_path="/usr/bin/docker")
    backend._daemon_info = lambda: {"OperatingSystem": "Docker Desktop"}

    assert backend.is_docker_desktop() is True
    assert "Docker Desktop" in backend.unavailable_reason()


def test_docker_backend_accepts_a_native_linux_engine(policy):
    from ingestion.capture.backends.docker_dumpcap import DockerDumpcapBackend

    backend = DockerDumpcapBackend(policy.docker, docker_path="/usr/bin/docker")
    backend._daemon_info = lambda: {"OperatingSystem": "Ubuntu 24.04"}

    assert backend.is_docker_desktop() is False


def test_missing_docker_cli_is_reported_clearly(policy):
    from ingestion.capture.backends.docker_dumpcap import DockerDumpcapBackend

    backend = DockerDumpcapBackend(policy.docker)
    # `docker_path=None` means "auto-discover", so absence must be forced.
    backend.docker_path = None

    assert backend.is_available() is False
    assert "docker CLI" in backend.unavailable_reason()


def test_unreachable_daemon_is_distinguished_from_a_missing_cli(policy):
    """Installed-but-stopped is the common case and needs its own message."""
    from ingestion.capture.backends.docker_dumpcap import DockerDumpcapBackend

    backend = DockerDumpcapBackend(policy.docker, docker_path="/usr/bin/docker")
    backend._daemon_info = lambda: None

    assert backend.is_available() is False
    assert "daemon is not reachable" in backend.unavailable_reason()


def test_local_backend_without_dumpcap_explains_itself():
    backend = LocalDumpcapBackend(dumpcap_path=None)
    backend.dumpcap_path = None

    assert backend.is_available() is False
    assert "Wireshark" in backend.unavailable_reason()


# ── Real capture (skipped when dumpcap is absent) ─────────────────────────────

_local = LocalDumpcapBackend()
_needs_dumpcap = pytest.mark.skipif(
    not _local.is_available(), reason="dumpcap is not installed on this host"
)


@_needs_dumpcap
def test_dumpcap_reports_a_version():
    assert "Dumpcap" in (LocalDumpcapBackend().version() or "")


@_needs_dumpcap
def test_interfaces_can_be_enumerated():
    interfaces = LocalDumpcapBackend().list_interfaces()

    assert interfaces
    assert all(i.identifier for i in interfaces)


@_needs_dumpcap
def test_unknown_interface_fails_with_the_available_list():
    with pytest.raises(CaptureBackendError, match="Available"):
        LocalDumpcapBackend().resolve_interface("definitely-not-an-interface")


@_needs_dumpcap
def test_friendly_interface_names_resolve():
    backend = LocalDumpcapBackend()
    first = backend.list_interfaces()[0]

    assert backend.resolve_interface(first.display_name) == first.identifier
    assert backend.resolve_interface(str(first.index)) == first.identifier
