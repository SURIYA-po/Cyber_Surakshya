"""Tests for the ingestion policy — loading, validation, fail-closed defaults."""
from __future__ import annotations

from dataclasses import replace

import pytest

from ingestion.config import (
    MAX_SNAPLEN,
    MIN_USEFUL_SNAPLEN,
    CaptureBackend,
    CapturePolicy,
    IngestionConfigError,
    IngestionPolicy,
)


@pytest.fixture
def policy(tmp_path) -> IngestionPolicy:
    """A valid policy pointed at a temp directory."""
    base = IngestionPolicy()
    return replace(
        base,
        capture=replace(
            base.capture, interface="eth0", output_dir=str(tmp_path / "captures")
        ),
    )


# ── Loading ───────────────────────────────────────────────────────────────────


def test_shipped_policy_file_loads():
    loaded = IngestionPolicy.load()

    assert loaded.loaded_from_defaults is False
    assert loaded.capture.snaplen == 96
    assert loaded.capture.rotate_seconds == 60
    assert loaded.capture.retain_files == 120


def test_shipped_policy_retains_two_hours():
    """60 s × 120 files, as specified for development."""
    assert IngestionPolicy.load().capture.retention_seconds == 7200


def test_missing_file_yields_fail_closed_defaults(tmp_path):
    loaded = IngestionPolicy.load(tmp_path / "absent.yaml")

    assert loaded.loaded_from_defaults is True
    assert loaded.capture.interface is None, "defaults must not name a network"
    assert loaded.capture.snaplen == 96


def test_corrupt_file_yields_defaults(tmp_path):
    path = tmp_path / "broken.yaml"
    path.write_text("capture: [not a mapping\n", encoding="utf-8")

    assert IngestionPolicy.load(path).loaded_from_defaults is True


def test_unknown_backend_falls_back_to_local(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text("capture:\n  backend: teleport\n  interface: eth0\n", encoding="utf-8")

    assert IngestionPolicy.load(path).capture.backend is CaptureBackend.LOCAL


def test_yaml_values_override_defaults(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text(
        "capture:\n"
        "  backend: docker\n"
        "  interface: ens33\n"
        "  snaplen: 128\n"
        "  bpf_filter: not port 22\n"
        "  rotate_seconds: 30\n"
        "  retain_files: 240\n",
        encoding="utf-8",
    )

    loaded = IngestionPolicy.load(path)

    assert loaded.capture.backend is CaptureBackend.DOCKER
    assert loaded.capture.interface == "ens33"
    assert loaded.capture.snaplen == 128
    assert loaded.capture.bpf_filter == "not port 22"
    assert loaded.capture.retention_seconds == 30 * 240


# ── The interface rule ────────────────────────────────────────────────────────


def test_start_is_refused_without_an_interface(tmp_path):
    """The platform must never guess which network to tap.

    A wrong interface does not fail — it silently captures the wrong traffic
    and fills the platform with confident detections about it.
    """
    base = IngestionPolicy()
    unset = replace(
        base, capture=replace(base.capture, output_dir=str(tmp_path / "c"))
    )

    with pytest.raises(IngestionConfigError, match="will not guess"):
        unset.validate_for_start(base_dir=tmp_path)


def test_valid_policy_passes_validation(policy, tmp_path):
    warnings = policy.validate_for_start(base_dir=tmp_path)

    assert warnings == []
    assert (tmp_path / "captures").is_dir()


# ── Snaplen ───────────────────────────────────────────────────────────────────


def test_snaplen_below_header_size_is_refused(policy, tmp_path):
    truncating = replace(
        policy, capture=replace(policy.capture, snaplen=MIN_USEFUL_SNAPLEN - 1)
    )

    with pytest.raises(IngestionConfigError, match="truncated"):
        truncating.validate_for_start(base_dir=tmp_path)


def test_snaplen_above_maximum_is_refused(policy, tmp_path):
    oversized = replace(policy, capture=replace(policy.capture, snaplen=MAX_SNAPLEN + 1))

    with pytest.raises(IngestionConfigError, match="maximum"):
        oversized.validate_for_start(base_dir=tmp_path)


def test_payload_capturing_snaplen_warns_but_is_allowed(policy, tmp_path):
    """An operator may need payloads; they should not be surprised by it."""
    full = replace(policy, capture=replace(policy.capture, snaplen=65535))

    warnings = full.validate_for_start(base_dir=tmp_path)

    assert any("payload" in w.lower() for w in warnings)
    assert any("PII" in w for w in warnings)


def test_header_only_snaplen_does_not_warn(policy, tmp_path):
    assert policy.capture.captures_full_payloads is False
    assert policy.validate_for_start(base_dir=tmp_path) == []


# ── Rotation and disk ─────────────────────────────────────────────────────────


def test_retain_files_below_two_is_refused(policy, tmp_path):
    """The newest file is always being written and cannot be processed."""
    too_few = replace(policy, capture=replace(policy.capture, retain_files=1))

    with pytest.raises(IngestionConfigError, match="at least 2"):
        too_few.validate_for_start(base_dir=tmp_path)


def test_zero_rotation_is_refused(policy, tmp_path):
    no_rotation = replace(policy, capture=replace(policy.capture, rotate_seconds=0))

    with pytest.raises(IngestionConfigError, match="rotate_seconds"):
        no_rotation.validate_for_start(base_dir=tmp_path)


def test_insufficient_disk_is_refused(policy, tmp_path):
    """A capture that fills the disk takes the whole platform down."""
    greedy = replace(
        policy, capture=replace(policy.capture, min_free_disk_mb=10**9)
    )

    with pytest.raises(IngestionConfigError, match="free"):
        greedy.validate_for_start(base_dir=tmp_path)


# ── Argument construction ─────────────────────────────────────────────────────


def test_dumpcap_arguments_carry_every_security_flag(policy, tmp_path):
    """Both backends share this, so a flag cannot be present in only one path."""
    from ingestion.capture.backends.base import CaptureBackend as Base

    args = Base.build_dumpcap_args(policy.capture, tmp_path)

    assert args[args.index("-i") + 1] == "eth0"
    assert args[args.index("-s") + 1] == "96"
    assert "duration:60" in args
    assert "files:120" in args
    assert "-q" in args


def test_bpf_filter_is_passed_when_set(policy, tmp_path):
    from ingestion.capture.backends.base import CaptureBackend as Base

    filtered = replace(policy.capture, bpf_filter="not port 22")

    args = Base.build_dumpcap_args(filtered, tmp_path)

    assert args[args.index("-f") + 1] == "not port 22"


def test_no_filter_flag_when_unset(policy, tmp_path):
    from ingestion.capture.backends.base import CaptureBackend as Base

    assert "-f" not in Base.build_dumpcap_args(policy.capture, tmp_path)
