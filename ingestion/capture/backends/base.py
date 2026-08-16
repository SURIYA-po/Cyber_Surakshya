"""Capture backend port.

Two backends produce byte-identical output into the same directory, so nothing
downstream knows or cares which ran:

  LocalDumpcapBackend  — this host's dumpcap binary.
  DockerDumpcapBackend — dumpcap in a container with --net=host.

The split exists because of a real platform constraint, not preference. On
Docker Desktop (Windows/macOS) the engine runs inside a Linux VM, so a
container's ``--net=host`` joins *that VM's* network namespace — not the
laptop's Wi-Fi. A capture started that way does not fail; it succeeds against
the wrong network. Only on a Linux host does ``--net=host`` mean what it reads
like.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


class CaptureBackendError(Exception):
    """Raised when a backend cannot start, stop, or inspect a capture."""


class CaptureUnavailableError(CaptureBackendError):
    """Raised when the backend's prerequisites are absent on this host.

    Distinct from a start failure: this means the backend can never work here
    (no dumpcap binary, no Docker daemon), so the caller should choose another
    rather than retry.
    """


@dataclass(frozen=True)
class CaptureHandle:
    """Identifies a running capture."""

    backend:     str
    identifier:  str                    # PID for local, container id for docker
    interface:   str
    output_dir:  Path
    file_prefix: str
    started_at:  datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


@dataclass(frozen=True)
class InterfaceInfo:
    """A capturable network interface."""

    identifier:   str          # what to pass to dumpcap -i
    display_name: str
    index:        int | None = None


class CaptureBackend(ABC):
    """Common contract for capture backends."""

    backend_name: str = "capture_backend"

    @abstractmethod
    def is_available(self) -> bool:
        """Return True when this backend can run on this host."""

    @abstractmethod
    def list_interfaces(self) -> list[InterfaceInfo]:
        """Enumerate capturable interfaces."""

    @abstractmethod
    def start(self, policy, output_dir: Path) -> CaptureHandle:
        """Begin a rotating capture. Raises CaptureBackendError on failure."""

    @abstractmethod
    def stop(self, handle: CaptureHandle, *, timeout: float = 10.0) -> bool:
        """Stop a capture. Returns True when it was running and is now stopped."""

    @abstractmethod
    def is_running(self, handle: CaptureHandle) -> bool:
        """Return True when the capture process is still alive."""

    def unavailable_reason(self) -> str:
        """Human-readable explanation for why this backend cannot run."""
        return f"{self.backend_name} is unavailable on this host."

    # ── Shared argument construction ──────────────────────────────────────────

    @staticmethod
    def build_dumpcap_args(policy, output_dir: Path) -> list[str]:
        """Build dumpcap arguments from a CapturePolicy.

        Shared by both backends so a security-relevant flag cannot be present
        in one path and missing from the other — snaplen in particular.

        ``-b duration:N -b files:M`` is dumpcap's native ring buffer: it closes
        and reopens a file every N seconds and reuses slots after M files. No
        cron job, no custom rotation logic, and a guarantee that file *k* is
        closed once file *k+1* exists.
        """
        target = output_dir / f"{policy.file_prefix}.pcap"
        args = [
            "-i", str(policy.interface),
            "-s", str(policy.snaplen),
            "-b", f"duration:{policy.rotate_seconds}",
            "-b", f"files:{policy.retain_files}",
            "-w", str(target),
            "-q",                      # no per-packet chatter on stderr
        ]
        if policy.bpf_filter:
            # Applied in the kernel, before packets reach userspace or disk.
            args += ["-f", policy.bpf_filter]
        return args
