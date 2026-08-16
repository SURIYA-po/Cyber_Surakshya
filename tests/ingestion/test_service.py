"""Tests for the ingestion control plane.

Starting a packet capture is the most privileged operation the platform
exposes. These tests pin the two properties that matter: it refuses to begin
without every dependency present, and it never reports a credential.
"""
from __future__ import annotations

import json
import time
from dataclasses import replace
from pathlib import Path

import pytest

from ingestion.config import IngestionPolicy
from ingestion.service import IngestionService, IngestionServiceError
from tests.ingestion.service_fixtures import FakeBackend, FakeRuntime

fakeredis = pytest.importorskip("fakeredis")


@pytest.fixture
def policy(tmp_path) -> IngestionPolicy:
    base = IngestionPolicy()
    return replace(
        base,
        capture=replace(
            base.capture, interface="eth0", output_dir=str(tmp_path / "captures")
        ),
        worker=replace(base.worker, poll_interval_seconds=1, sweep_interval_seconds=1),
    )


@pytest.fixture
def client():
    return fakeredis.FakeRedis(decode_responses=True)


@pytest.fixture
def service(policy, client, tmp_path) -> IngestionService:
    svc = IngestionService(
        FakeRuntime(), policy=policy, base_dir=tmp_path, redis_client=client
    )
    svc.session._backend = FakeBackend()
    return svc


# ── Preflight ─────────────────────────────────────────────────────────────────


def test_preflight_reports_ready_when_everything_is_present(service):
    result = service.preflight()

    assert result.ready is True
    assert result.blockers == []
    assert result.checks == {
        "capture_backend": True,
        "capture_policy":  True,
        "stream":          True,
        "normalizer":      True,
        "runtime":         True,
    }


def test_preflight_blocks_when_redis_is_unreachable(policy, tmp_path):
    """A capture without a stream fills the disk with pcaps going nowhere."""

    class DeadClient:
        def ping(self):
            raise ConnectionError("connection refused")

    service = IngestionService(
        FakeRuntime(), policy=policy, base_dir=tmp_path, redis_client=DeadClient()
    )
    service.session._backend = FakeBackend()

    result = service.preflight()

    assert result.ready is False
    assert result.checks["stream"] is False
    assert any("Redis is unreachable" in b for b in result.blockers)
    assert any("docker compose" in b for b in result.blockers), "must be actionable"


def test_preflight_blocks_without_a_capture_backend(service):
    service.session._backend = FakeBackend(available=False)

    result = service.preflight()

    assert result.ready is False
    assert result.checks["capture_backend"] is False


def test_preflight_blocks_without_an_interface(client, tmp_path):
    """The platform must never guess which network to tap."""
    base = IngestionPolicy()
    unset = replace(
        base, capture=replace(base.capture, output_dir=str(tmp_path / "c"))
    )
    service = IngestionService(
        FakeRuntime(), policy=unset, base_dir=tmp_path, redis_client=client
    )
    service.session._backend = FakeBackend()

    result = service.preflight()

    assert result.ready is False
    assert result.checks["capture_policy"] is False


def test_preflight_changes_nothing(service):
    service.preflight()

    assert service.is_running() is False
    assert service.session.backend.starts == 0


# ── Fail closed ───────────────────────────────────────────────────────────────


def test_start_is_refused_when_preflight_fails(policy, tmp_path):
    class DeadClient:
        def ping(self):
            raise ConnectionError("refused")

    service = IngestionService(
        FakeRuntime(), policy=policy, base_dir=tmp_path, redis_client=DeadClient()
    )
    backend = FakeBackend()
    service.session._backend = backend

    with pytest.raises(IngestionServiceError, match="Redis is unreachable"):
        service.start()

    assert backend.starts == 0, "capture must not begin without a stream"
    assert service.is_running() is False


def test_capture_does_not_start_without_an_interface(client, tmp_path):
    base = IngestionPolicy()
    unset = replace(
        base, capture=replace(base.capture, output_dir=str(tmp_path / "c"))
    )
    service = IngestionService(
        FakeRuntime(), policy=unset, base_dir=tmp_path, redis_client=client
    )
    backend = FakeBackend()
    service.session._backend = backend

    with pytest.raises(IngestionServiceError):
        service.start()

    assert backend.starts == 0


# ── Lifecycle ─────────────────────────────────────────────────────────────────


def test_start_then_stop(service):
    service.start()
    assert service.is_running() is True
    assert service.session.backend.running is True

    service.stop()

    assert service.is_running() is False
    assert service.session.backend.running is False


def test_double_start_is_a_conflict(service):
    service.start()
    try:
        with pytest.raises(IngestionServiceError, match="already running"):
            service.start()
    finally:
        service.stop()


def test_stop_is_idempotent(service):
    assert service.stop()["running"] is False
    service.start()
    service.stop()
    assert service.stop()["running"] is False


def test_start_accepts_an_interface_override(service):
    service.start(interface="eth1")
    try:
        assert service.policy.capture.interface == "eth1"
    finally:
        service.stop()


def test_worker_thread_is_a_daemon(service):
    """A hung worker must not keep the process alive."""
    service.start()
    try:
        assert service._thread.daemon is True
    finally:
        service.stop()


def test_worker_polls_while_running(service):
    service.start()
    try:
        time.sleep(2.5)
        assert service.stats.polls >= 1
        assert service.stats.errors == 0
    finally:
        service.stop()


# ── Status ────────────────────────────────────────────────────────────────────


def test_status_never_reports_credentials(policy, client, tmp_path, monkeypatch):
    """A status endpoint that leaks the password defeats the ACL entirely."""
    monkeypatch.setenv(policy.stream.password_env, "super-secret-password")
    service = IngestionService(
        FakeRuntime(), policy=policy, base_dir=tmp_path, redis_client=client
    )
    service.session._backend = FakeBackend()
    service.start()
    try:
        blob = json.dumps(service.status()) + json.dumps(service.preflight().as_dict())
    finally:
        service.stop()

    assert "super-secret-password" not in blob


def test_status_omits_the_redis_url(service):
    service.start()
    try:
        assert "url" not in service.status()["stream"]
    finally:
        service.stop()


def test_status_reports_the_capture_policy(service):
    status = service.status()

    assert status["policy"]["snaplen"] == 96
    assert status["policy"]["retention_seconds"] == 7200
    assert status["running"] is False


def test_status_is_available_before_starting(service):
    status = service.status()

    assert status["running"] is False
    assert status["capture"]["running"] is False
    assert status["stream"]["reachable"] is False


def test_status_includes_worker_counters(service):
    service.start()
    try:
        time.sleep(1.5)
        worker = service.status()["worker"]
        assert worker["started_at"] is not None
        assert "consecutive_errors" in worker
    finally:
        service.stop()


# ── Resilience ────────────────────────────────────────────────────────────────


def test_worker_survives_an_iteration_failure(service, monkeypatch):
    """One bad poll must not kill live ingestion."""
    service.start()
    try:
        def boom():
            raise RuntimeError("transient failure")

        monkeypatch.setattr(service.session, "ready_files", boom)
        time.sleep(2.5)

        assert service.stats.errors >= 1
        assert service.is_running() is True, "the worker must keep going"
    finally:
        service.stop()


def test_worker_gives_up_after_repeated_failures(policy, client, tmp_path, monkeypatch):
    """An unreachable dependency must not spin at full speed forever."""
    tight = replace(
        policy, worker=replace(policy.worker, max_consecutive_errors=2, poll_interval_seconds=1)
    )
    service = IngestionService(
        FakeRuntime(), policy=tight, base_dir=tmp_path, redis_client=client
    )
    service.session._backend = FakeBackend()
    service.start()
    try:
        def boom():
            raise RuntimeError("dependency down")

        monkeypatch.setattr(service.session, "ready_files", boom)
        deadline = time.time() + 10
        while service.is_running() and time.time() < deadline:
            time.sleep(0.5)

        assert service.is_running() is False
        assert service.stats.consecutive_errors >= 2
        assert service.stats.last_error is not None
    finally:
        service.stop()


def test_interfaces_are_listed_for_the_picker(service):
    interfaces = service.list_interfaces()

    assert interfaces
    assert interfaces[0]["identifier"] == "eth0"


def test_interfaces_error_when_the_backend_is_unavailable(service):
    service.session._backend = FakeBackend(available=False)

    with pytest.raises(IngestionServiceError):
        service.list_interfaces()
