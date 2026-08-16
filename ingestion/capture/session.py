"""Capture session — the lifecycle behind the frontend's "Go Live" control.

Owns backend selection, policy validation, start/stop, health, and retention.
Everything above it (the API in Phase 4) sees one object with four verbs.

Backend selection is automatic but never silent: if the configured backend
cannot run here, the session says which one it chose and why, rather than
falling back quietly. Capture is the platform's highest-privilege operation
and the one where a wrong choice produces plausible-looking data about the
wrong network.
"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ingestion.capture.backends.base import (
    CaptureBackend,
    CaptureBackendError,
    CaptureHandle,
    CaptureUnavailableError,
)
from ingestion.capture.backends.docker_dumpcap import DockerDumpcapBackend
from ingestion.capture.backends.local_dumpcap import LocalDumpcapBackend
from ingestion.capture.retention import (
    RetentionResult,
    list_capture_files,
    newest_file,
    sweep,
)
from ingestion.config import (
    CaptureBackend as BackendChoice,
)
from ingestion.config import (
    IngestionConfigError,
    IngestionPolicy,
)

logger = logging.getLogger(__name__)


class CaptureSessionError(Exception):
    """Raised when a capture session cannot perform the requested action."""


@dataclass
class CaptureStatus:
    """A point-in-time view of the capture, for the API and dashboard."""

    running:         bool = False
    backend:         str | None = None
    interface:       str | None = None
    started_at:      datetime | None = None
    uptime_seconds:  float = 0.0
    snaplen:         int = 0
    bpf_filter:      str | None = None
    rotate_seconds:  int = 0
    retain_files:    int = 0
    retention_seconds: int = 0
    output_dir:      str | None = None
    file_count:      int = 0
    total_bytes:     int = 0
    oldest_file_age_seconds: float | None = None
    active_file:     str | None = None
    ready_file_count: int = 0
    warnings:        list[str] = field(default_factory=list)
    last_error:      str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "running":            self.running,
            "backend":            self.backend,
            "interface":          self.interface,
            "started_at":         self.started_at.isoformat() if self.started_at else None,
            "uptime_seconds":     round(self.uptime_seconds, 1),
            "snaplen":            self.snaplen,
            "bpf_filter":         self.bpf_filter,
            "rotate_seconds":     self.rotate_seconds,
            "retain_files":       self.retain_files,
            "retention_seconds":  self.retention_seconds,
            "output_dir":         self.output_dir,
            "file_count":         self.file_count,
            "total_bytes":        self.total_bytes,
            "total_mb":           round(self.total_bytes / 1_048_576, 2),
            "oldest_file_age_seconds": self.oldest_file_age_seconds,
            "active_file":        self.active_file,
            "ready_file_count":   self.ready_file_count,
            "warnings":           list(self.warnings),
            "last_error":         self.last_error,
        }
        return payload


class CaptureSession:
    """Starts, stops, and reports on a rotating network capture."""

    def __init__(
        self,
        policy: IngestionPolicy | None = None,
        *,
        backend: CaptureBackend | None = None,
        base_dir: Path | None = None,
    ) -> None:
        self.policy   = policy or IngestionPolicy.load()
        self.base_dir = base_dir or Path.cwd()
        self._lock    = threading.Lock()
        self._handle: CaptureHandle | None = None
        self._warnings: list[str] = []
        self._last_error: str | None = None
        self._backend = backend or self._select_backend()

    # ── Backend selection ─────────────────────────────────────────────────────

    def _select_backend(self) -> CaptureBackend:
        """Choose a usable backend, recording any substitution as a warning."""
        choice = self.policy.capture.backend

        if choice is BackendChoice.DOCKER:
            docker = DockerDumpcapBackend(self.policy.docker)
            if docker.is_available() and not docker.is_docker_desktop():
                return docker
            reason = docker.unavailable_reason()
            local = LocalDumpcapBackend()
            if local.is_available():
                self._warnings.append(
                    f"Configured backend 'docker' cannot be used: {reason} "
                    "Falling back to 'local'."
                )
                logger.warning(
                    "capture_backend_substituted",
                    extra={"configured": "docker", "using": "local", "reason": reason},
                )
                return local
            self._warnings.append(
                f"Neither backend is available. docker: {reason} "
                f"local: {local.unavailable_reason()}"
            )
            return docker

        local = LocalDumpcapBackend()
        if not local.is_available():
            self._warnings.append(
                f"Configured backend 'local' cannot be used: "
                f"{local.unavailable_reason()}"
            )
        return local

    @property
    def backend(self) -> CaptureBackend:
        return self._backend

    @property
    def output_dir(self) -> Path:
        return self.policy.capture.resolved_output_dir(self.base_dir)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> CaptureStatus:
        """Validate the policy and begin capturing.

        Raises:
            CaptureSessionError: the capture cannot start safely.
        """
        with self._lock:
            if self._handle is not None and self._backend.is_running(self._handle):
                raise CaptureSessionError(
                    "A capture is already running. Stop it before starting another."
                )

            if not self._backend.is_available():
                raise CaptureSessionError(self._backend.unavailable_reason())

            try:
                policy_warnings = self.policy.validate_for_start(base_dir=self.base_dir)
            except IngestionConfigError as exc:
                self._last_error = str(exc)
                raise CaptureSessionError(str(exc)) from exc

            for warning in policy_warnings:
                logger.warning("capture_policy_warning", extra={"warning": warning})

            try:
                handle = self._backend.start(self.policy.capture, self.output_dir)
            except (CaptureBackendError, CaptureUnavailableError) as exc:
                self._last_error = str(exc)
                raise CaptureSessionError(str(exc)) from exc

            self._handle = handle
            self._last_error = None
            self._warnings = [w for w in self._warnings if "Falling back" in w]
            self._warnings.extend(policy_warnings)

            logger.info(
                "capture_session_started",
                extra={
                    "backend":   handle.backend,
                    "interface": handle.interface,
                    "output_dir": str(handle.output_dir),
                    "retention_seconds": self.policy.capture.retention_seconds,
                },
            )
            return self._status_locked()

    def stop(self) -> CaptureStatus:
        """Stop the capture. Idempotent — stopping a stopped session is fine."""
        with self._lock:
            if self._handle is None:
                return self._status_locked()
            try:
                self._backend.stop(self._handle)
            except CaptureBackendError as exc:
                self._last_error = str(exc)
                logger.warning("capture_session_stop_failed", extra={"error": str(exc)})
            finally:
                self._handle = None
            logger.info("capture_session_stopped", extra={})
            return self._status_locked()

    def is_running(self) -> bool:
        with self._lock:
            return self._handle is not None and self._backend.is_running(self._handle)

    def status(self) -> CaptureStatus:
        with self._lock:
            return self._status_locked()

    # ── Retention ─────────────────────────────────────────────────────────────

    def sweep_retention(self) -> RetentionResult:
        """Enforce the retention window and size ceiling."""
        cap = self.policy.capture
        return sweep(
            self.output_dir,
            prefix=cap.file_prefix,
            max_age_seconds=cap.retention_seconds,
            max_total_bytes=cap.max_total_size_mb * 1_048_576,
            keep_newest=True,
        )

    def ready_files(self) -> list[Path]:
        """Closed capture files, oldest first — safe for Phase 3 to process.

        Excludes the newest file, which dumpcap is still writing. Reading it
        would yield a truncated final packet and a corrupt final flow.
        """
        cap = self.policy.capture
        files = list_capture_files(self.output_dir, cap.file_prefix)
        return [f.path for f in files[:-1]] if len(files) > 1 else []

    # ── Diagnostics ───────────────────────────────────────────────────────────

    def list_interfaces(self) -> list[dict[str, Any]]:
        """Enumerate capturable interfaces for the frontend's picker."""
        if not self._backend.is_available():
            raise CaptureSessionError(self._backend.unavailable_reason())
        try:
            return [
                {
                    "identifier":   info.identifier,
                    "display_name": info.display_name,
                    "index":        info.index,
                }
                for info in self._backend.list_interfaces()
            ]
        except CaptureBackendError as exc:
            raise CaptureSessionError(str(exc)) from exc

    def _status_locked(self) -> CaptureStatus:
        cap     = self.policy.capture
        running = self._handle is not None and self._backend.is_running(self._handle)
        files   = list_capture_files(self.output_dir, cap.file_prefix)
        active  = newest_file(self.output_dir, cap.file_prefix)

        uptime = 0.0
        if self._handle is not None:
            uptime = (
                datetime.now(timezone.utc) - self._handle.started_at
            ).total_seconds()

        return CaptureStatus(
            running=running,
            backend=self._backend.backend_name,
            interface=(self._handle.interface if self._handle else cap.interface),
            started_at=(self._handle.started_at if self._handle else None),
            uptime_seconds=uptime,
            snaplen=cap.snaplen,
            bpf_filter=cap.bpf_filter or None,
            rotate_seconds=cap.rotate_seconds,
            retain_files=cap.retain_files,
            retention_seconds=cap.retention_seconds,
            output_dir=str(self.output_dir),
            file_count=len(files),
            total_bytes=sum(f.size_bytes for f in files),
            oldest_file_age_seconds=(round(files[0].age_seconds, 1) if files else None),
            active_file=(active.name if active else None),
            ready_file_count=max(0, len(files) - 1),
            warnings=list(self._warnings),
            last_error=self._last_error,
        )
