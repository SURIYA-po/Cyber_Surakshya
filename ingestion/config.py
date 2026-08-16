"""Ingestion policy configuration — loading, validation, fail-closed defaults.

Mirrors agents/response/config.py: the policy that governs a privileged
operation is data, not code, and every failure path degrades toward doing
less rather than more.

One rule is stricter here than anywhere else in the platform: **there is no
default capture interface.** A wrong interface does not fail — it silently
taps the wrong network and fills the platform with confident detections about
traffic nobody asked it to watch. Refusing to start is the only safe default.
"""
from __future__ import annotations

import logging
import os
import shutil
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[1] / "config" / "ingestion_policy.yaml"

# Wireshark's own maximum; beyond this dumpcap rejects the argument.
MAX_SNAPLEN = 262144

# Enough for full TCP/IP headers plus options. Below this, flow features start
# to degrade because header lengths cannot be read.
MIN_USEFUL_SNAPLEN = 64


class CaptureBackend(str, Enum):
    """Where dumpcap runs.

    LOCAL  — this host's dumpcap binary. Required on Docker Desktop, where a
             Linux container's --net=host joins the Docker VM's network
             namespace, not the Windows/macOS host's.
    DOCKER — a container with --net=host. Correct on Linux hosts.
    """

    LOCAL  = "local"
    DOCKER = "docker"


class IngestionConfigError(Exception):
    """Raised when the ingestion policy cannot support a safe capture."""


@dataclass(frozen=True)
class DockerPolicy:
    """Container settings for the docker backend."""

    image:            str = "cyber-surakshya/capture:latest"
    container_name:   str = "cs-capture"
    cap_add:          tuple[str, ...] = ("NET_RAW", "NET_ADMIN")
    network_mode:     str = "host"
    read_only_rootfs: bool = True
    user:             str = "pcap"


@dataclass(frozen=True)
class CapturePolicy:
    """How the platform taps a network and what it retains."""

    backend:        CaptureBackend = CaptureBackend.LOCAL
    interface:      str | None = None          # no default, deliberately
    snaplen:        int = 96
    bpf_filter:     str = ""
    rotate_seconds: int = 60
    retain_files:   int = 120
    output_dir:     str = "captures"
    file_prefix:    str = "cs"
    min_free_disk_mb:  int = 512
    max_total_size_mb: int = 4096

    @property
    def retention_seconds(self) -> int:
        """Total retention window implied by the ring buffer."""
        return self.rotate_seconds * self.retain_files

    @property
    def captures_full_payloads(self) -> bool:
        """True when the snaplen is large enough to record packet payloads."""
        return self.snaplen == 0 or self.snaplen > 256

    def resolved_output_dir(self, base: Path | None = None) -> Path:
        path = Path(self.output_dir)
        if not path.is_absolute():
            path = (base or Path.cwd()) / path
        return path


@dataclass(frozen=True)
class StreamPolicy:
    """Redis Streams transport between capture and the agent pipeline.

    Credentials are read from the environment, never stored here — a policy
    file is committed, and a password in a committed file is a password in the
    repository history forever.
    """

    url:              str = "redis://127.0.0.1:6379/0"
    username_env:     str = "INGESTION_REDIS_USERNAME"
    password_env:     str = "INGESTION_REDIS_PASSWORD"

    # Per-role credentials. Without these the producer and consumer would
    # share one identity, and the least-privilege split in docker/redis/
    # users.acl — where the producer cannot read the stream — would apply to
    # nothing the platform actually runs. Both fall back to the general pair
    # when unset, so a single-user deployment still works.
    producer_username_env: str = "INGESTION_REDIS_PRODUCER_USERNAME"
    producer_password_env: str = "INGESTION_REDIS_PRODUCER_PASSWORD"
    consumer_username_env: str = "INGESTION_REDIS_CONSUMER_USERNAME"
    consumer_password_env: str = "INGESTION_REDIS_CONSUMER_PASSWORD"

    stream_key:       str = "cs:flows"
    group:            str = "cs-pipeline"
    consumer_prefix:  str = "worker"

    max_length:       int  = 100_000
    approximate_trim: bool = True

    batch_size:       int = 50
    block_ms:         int = 5_000

    claim_idle_ms:         int = 60_000
    max_delivery_attempts: int = 5
    dead_letter_key:       str = "cs:flows:dead"

    dedup_ttl_seconds: int = 900
    dedup_key_prefix:  str = "cs:dedup:"

    fail_closed: bool = True

    @property
    def username(self) -> str | None:
        """ACL username from the environment, if set."""
        return os.environ.get(self.username_env) or None

    @property
    def password(self) -> str | None:
        """Password from the environment, if set."""
        return os.environ.get(self.password_env) or None

    def credentials(self, role: str | None = None) -> tuple[str | None, str | None]:
        """Return (username, password) for a role, falling back to the general pair.

        ``role`` is "producer", "consumer", or None. An unknown role falls back
        rather than failing: a typo must not silently produce an unauthenticated
        connection.
        """
        if role == "producer":
            user = os.environ.get(self.producer_username_env)
            secret = os.environ.get(self.producer_password_env)
        elif role == "consumer":
            user = os.environ.get(self.consumer_username_env)
            secret = os.environ.get(self.consumer_password_env)
        else:
            user = secret = None
        return (user or self.username, secret or self.password)

    @property
    def is_authenticated(self) -> bool:
        return self.password is not None

    @property
    def is_loopback(self) -> bool:
        """True when Redis is on this host and not exposed to a network."""
        return any(host in self.url for host in ("127.0.0.1", "localhost", "::1"))

    @property
    def uses_tls(self) -> bool:
        return self.url.startswith("rediss://")


@dataclass(frozen=True)
class WorkerPolicy:
    """Background loop that moves captures into the pipeline."""

    poll_interval_seconds:  int = 5
    max_batches_per_poll:   int = 4
    sweep_interval_seconds: int = 300
    max_consecutive_errors: int = 10


@dataclass(frozen=True)
class UploadPolicy:
    """Remote pcap submission — ingress for sensors that are not this host.

    A local capture is bounded by the interface it taps and by dumpcap's ring
    buffer. An HTTP ingress is bounded by nothing at all except what is written
    here, and it is reachable by anything holding the API key. Every limit that
    keeps a remote sender from exhausting this host's disk or CPU lives in this
    block, and each one is enforced *while* the body is read, not after.
    """

    #: Rejected past this size, mid-upload. cicflowmeter reassembles flows in
    #: memory, so a large pcap costs far more than its bytes on disk.
    max_file_mb: int = 256

    #: Where a submission lands while it is being processed. Separate from the
    #: capture ring so a remote sender can never interfere with local capture
    #: files or with the retention window that governs them.
    work_dir: str = "uploads"

    #: Safety net only: a submission is deleted the moment it is processed.
    #: This bounds what a crash mid-processing can leave behind.
    retention_seconds: int = 3600

    allowed_suffixes: tuple[str, ...] = (".pcap", ".pcapng", ".cap")

    @property
    def max_file_bytes(self) -> int:
        return self.max_file_mb * 1_048_576

    def resolved_work_dir(self, base: Path | None = None) -> Path:
        path = Path(self.work_dir)
        if not path.is_absolute():
            path = (base or Path.cwd()) / path
        return path


@dataclass(frozen=True)
class IngestionPolicy:
    """Complete ingestion configuration."""

    capture: CapturePolicy = field(default_factory=CapturePolicy)
    stream:  StreamPolicy  = field(default_factory=StreamPolicy)
    worker:  WorkerPolicy  = field(default_factory=WorkerPolicy)
    docker:  DockerPolicy  = field(default_factory=DockerPolicy)
    upload:  UploadPolicy  = field(default_factory=UploadPolicy)

    loaded_from_defaults: bool = True
    source_path:          str | None = None

    # ── Loading ───────────────────────────────────────────────────────────────

    @classmethod
    def load(cls, path: str | os.PathLike[str] | None = None) -> IngestionPolicy:
        """Load policy from YAML, falling back to fail-closed defaults.

        Never raises. Structural problems degrade to defaults; the resulting
        policy still refuses to start a capture without an explicit interface,
        so a broken config cannot cause an accidental tap.
        """
        config_path = Path(path) if path else Path(
            os.environ.get("INGESTION_POLICY_PATH", DEFAULT_CONFIG_PATH)
        )
        try:
            import yaml
        except ImportError:
            logger.warning(
                "ingestion_policy_pyyaml_missing", extra={"path": str(config_path)}
            )
            return cls()

        if not config_path.is_file():
            logger.warning(
                "ingestion_policy_file_missing_using_defaults",
                extra={"path": str(config_path)},
            )
            return cls()

        try:
            raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
            if not isinstance(raw, dict):
                raise ValueError("Ingestion policy root must be a mapping.")
            policy = cls._from_mapping(raw, config_path)
        except Exception as exc:
            logger.error(
                "ingestion_policy_load_failed_using_defaults",
                extra={"path": str(config_path), "error": str(exc)},
            )
            return cls()

        logger.info(
            "ingestion_policy_loaded",
            extra={
                "path":      str(config_path),
                "backend":   policy.capture.backend.value,
                "interface": policy.capture.interface,
                "snaplen":   policy.capture.snaplen,
                "retention_seconds": policy.capture.retention_seconds,
            },
        )
        return policy

    @classmethod
    def _from_mapping(cls, raw: dict[str, Any], path: Path) -> IngestionPolicy:
        defaults = CapturePolicy()
        cap = raw.get("capture") or {}

        try:
            backend = CaptureBackend(str(cap.get("backend", "local")).lower())
        except ValueError:
            logger.warning(
                "ingestion_policy_unknown_backend",
                extra={"backend": cap.get("backend")},
            )
            backend = CaptureBackend.LOCAL

        interface = cap.get("interface")
        interface = str(interface).strip() if interface else None

        capture = CapturePolicy(
            backend=backend,
            interface=interface or None,
            snaplen=int(cap.get("snaplen", defaults.snaplen)),
            bpf_filter=str(cap.get("bpf_filter", "") or "").strip(),
            rotate_seconds=int(cap.get("rotate_seconds", defaults.rotate_seconds)),
            retain_files=int(cap.get("retain_files", defaults.retain_files)),
            output_dir=str(cap.get("output_dir", defaults.output_dir)),
            file_prefix=str(cap.get("file_prefix", defaults.file_prefix)),
            min_free_disk_mb=int(cap.get("min_free_disk_mb", defaults.min_free_disk_mb)),
            max_total_size_mb=int(cap.get("max_total_size_mb", defaults.max_total_size_mb)),
        )

        stream_defaults = StreamPolicy()
        stm = raw.get("stream") or {}
        stream = StreamPolicy(
            url=str(stm.get("url", stream_defaults.url)),
            username_env=str(stm.get("username_env", stream_defaults.username_env)),
            password_env=str(stm.get("password_env", stream_defaults.password_env)),
            stream_key=str(stm.get("stream_key", stream_defaults.stream_key)),
            group=str(stm.get("group", stream_defaults.group)),
            consumer_prefix=str(stm.get("consumer_prefix", stream_defaults.consumer_prefix)),
            max_length=int(stm.get("max_length", stream_defaults.max_length)),
            approximate_trim=bool(stm.get("approximate_trim", True)),
            batch_size=int(stm.get("batch_size", stream_defaults.batch_size)),
            block_ms=int(stm.get("block_ms", stream_defaults.block_ms)),
            claim_idle_ms=int(stm.get("claim_idle_ms", stream_defaults.claim_idle_ms)),
            max_delivery_attempts=int(
                stm.get("max_delivery_attempts", stream_defaults.max_delivery_attempts)
            ),
            dead_letter_key=str(stm.get("dead_letter_key", stream_defaults.dead_letter_key)),
            dedup_ttl_seconds=int(
                stm.get("dedup_ttl_seconds", stream_defaults.dedup_ttl_seconds)
            ),
            dedup_key_prefix=str(stm.get("dedup_key_prefix", stream_defaults.dedup_key_prefix)),
            fail_closed=bool(stm.get("fail_closed", True)),
        )

        worker_defaults = WorkerPolicy()
        wrk = raw.get("worker") or {}
        worker = WorkerPolicy(
            poll_interval_seconds=int(
                wrk.get("poll_interval_seconds", worker_defaults.poll_interval_seconds)
            ),
            max_batches_per_poll=int(
                wrk.get("max_batches_per_poll", worker_defaults.max_batches_per_poll)
            ),
            sweep_interval_seconds=int(
                wrk.get("sweep_interval_seconds", worker_defaults.sweep_interval_seconds)
            ),
            max_consecutive_errors=int(
                wrk.get("max_consecutive_errors", worker_defaults.max_consecutive_errors)
            ),
        )

        dock = raw.get("docker") or {}
        docker = DockerPolicy(
            image=str(dock.get("image", DockerPolicy.image)),
            container_name=str(dock.get("container_name", DockerPolicy.container_name)),
            cap_add=tuple(str(c) for c in (dock.get("cap_add") or DockerPolicy.cap_add)),
            network_mode=str(dock.get("network_mode", DockerPolicy.network_mode)),
            read_only_rootfs=bool(dock.get("read_only_rootfs", True)),
            user=str(dock.get("user", DockerPolicy.user)),
        )

        upload_defaults = UploadPolicy()
        upl = raw.get("upload") or {}
        suffixes = upl.get("allowed_suffixes") or upload_defaults.allowed_suffixes
        upload = UploadPolicy(
            max_file_mb=int(upl.get("max_file_mb", upload_defaults.max_file_mb)),
            work_dir=str(upl.get("work_dir", upload_defaults.work_dir)),
            retention_seconds=int(
                upl.get("retention_seconds", upload_defaults.retention_seconds)
            ),
            allowed_suffixes=tuple(
                str(s).lower() if str(s).startswith(".") else f".{str(s).lower()}"
                for s in suffixes
            ),
        )

        return cls(
            capture=capture,
            stream=stream,
            worker=worker,
            docker=docker,
            upload=upload,
            loaded_from_defaults=False,
            source_path=str(path),
        )

    # ── Validation ────────────────────────────────────────────────────────────

    def validate_for_start(self, *, base_dir: Path | None = None) -> list[str]:
        """Check the policy can support a capture. Returns non-fatal warnings.

        Raises:
            IngestionConfigError: the capture must not start.
        """
        cap = self.capture
        warnings: list[str] = []

        if not cap.interface:
            raise IngestionConfigError(
                "capture.interface is not set. The platform will not guess "
                "which network to tap — a wrong interface does not fail, it "
                "silently captures the wrong traffic. Set it in "
                "config/ingestion_policy.yaml (list options with `dumpcap -D`)."
            )

        if cap.snaplen != 0 and cap.snaplen < MIN_USEFUL_SNAPLEN:
            raise IngestionConfigError(
                f"capture.snaplen={cap.snaplen} is below {MIN_USEFUL_SNAPLEN} "
                "bytes; TCP/IP headers would be truncated and flow features "
                "would silently degrade."
            )
        if cap.snaplen > MAX_SNAPLEN:
            raise IngestionConfigError(
                f"capture.snaplen={cap.snaplen} exceeds the {MAX_SNAPLEN} maximum."
            )
        if cap.captures_full_payloads:
            warnings.append(
                f"snaplen={cap.snaplen} records packet payloads, not just "
                "headers. Credentials, tokens, and PII will be written to disk. "
                "Flow features need only headers — consider 96."
            )

        if cap.rotate_seconds < 1:
            raise IngestionConfigError("capture.rotate_seconds must be at least 1.")
        if cap.retain_files < 2:
            raise IngestionConfigError(
                "capture.retain_files must be at least 2 — the newest file is "
                "still being written and cannot be processed."
            )

        self._require_writable_dir(cap.resolved_output_dir(base_dir), "capture")

        return warnings

    def validate_for_remote(self, *, base_dir: Path | None = None) -> list[str]:
        """Check the policy can accept submitted pcaps. Returns warnings.

        Deliberately *not* `validate_for_start`: remote mode taps nothing, so
        demanding an interface, a snaplen, or a ring buffer would block an
        operator whose only sensors are elsewhere. What it does keep is the
        part that protects this host — a writable directory with headroom.

        Raises:
            IngestionConfigError: submissions must not be accepted.
        """
        upl = self.upload
        warnings: list[str] = []

        if upl.max_file_mb < 1:
            raise IngestionConfigError(
                "upload.max_file_mb must be at least 1; a zero ceiling rejects "
                "every submission."
            )
        if upl.max_file_mb > 2048:
            warnings.append(
                f"upload.max_file_mb={upl.max_file_mb} allows a single sender to "
                "push 2 GB+ into memory during flow extraction. 256 is ample for "
                "a rotating remote sensor."
            )
        if not upl.allowed_suffixes:
            raise IngestionConfigError(
                "upload.allowed_suffixes is empty; nothing could ever be accepted."
            )

        self._require_writable_dir(upl.resolved_work_dir(base_dir), "upload")

        warnings.append(
            "Remote ingest is open: any caller with the API key can submit "
            "traffic that the pipeline will treat as observed reality. Flows "
            "carry the sender's addresses, not this host's — attribution in "
            "alerts is only as trustworthy as the sender."
        )
        return warnings

    def _require_writable_dir(self, directory: Path, label: str) -> None:
        """Create a directory and refuse the operation if the disk is tight."""
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            raise IngestionConfigError(
                f"Cannot create {label} directory {directory}: {exc}"
            ) from exc

        free_mb = shutil.disk_usage(directory).free / (1024 * 1024)
        if free_mb < self.capture.min_free_disk_mb:
            raise IngestionConfigError(
                f"Only {free_mb:.0f} MB free at {directory}; policy requires "
                f"{self.capture.min_free_disk_mb} MB. Ingestion that fills the "
                "disk takes the whole platform down with it."
            )

    def with_interface(self, interface: str) -> IngestionPolicy:
        """Return a copy targeting a different interface."""
        return replace(self, capture=replace(self.capture, interface=interface))
