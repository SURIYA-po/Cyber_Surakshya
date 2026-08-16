"""Capture backends — local process and containerised."""
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

__all__ = [
    "CaptureBackend",
    "CaptureBackendError",
    "CaptureHandle",
    "CaptureUnavailableError",
    "DockerDumpcapBackend",
    "InterfaceInfo",
    "LocalDumpcapBackend",
]
