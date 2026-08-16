"""Network capture layer."""
from __future__ import annotations

from ingestion.capture.backends.base import (
    CaptureBackend,
    CaptureBackendError,
    CaptureHandle,
    CaptureUnavailableError,
    InterfaceInfo,
)
from ingestion.capture.backends.docker_dumpcap import DockerDumpcapBackend
from ingestion.capture.backends.local_dumpcap import LocalDumpcapBackend
from ingestion.capture.retention import (
    CaptureFile,
    RetentionResult,
    list_capture_files,
    newest_file,
    sweep,
)
from ingestion.capture.session import (
    CaptureSession,
    CaptureSessionError,
    CaptureStatus,
)

__all__ = [
    "CaptureBackend",
    "CaptureBackendError",
    "CaptureFile",
    "CaptureHandle",
    "CaptureSession",
    "CaptureSessionError",
    "CaptureStatus",
    "CaptureUnavailableError",
    "DockerDumpcapBackend",
    "InterfaceInfo",
    "LocalDumpcapBackend",
    "RetentionResult",
    "list_capture_files",
    "newest_file",
    "sweep",
]
