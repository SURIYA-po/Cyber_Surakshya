"""Test doubles shared by the ingestion service suites.

Extracted from test_service.py when remote-submission tests needed the same
two doubles. Both suites drive `IngestionService`, and a capture backend that
diverges between them would let one suite pass against behaviour the other
does not have.
"""
from __future__ import annotations

from pathlib import Path


class FakeBackend:
    """Capture backend double — never touches the network."""

    backend_name = "fake"

    def __init__(self, *, available: bool = True):
        self.available = available
        self.running = False
        self.starts = 0

    def is_available(self):
        return self.available

    def unavailable_reason(self):
        return "fake backend unavailable"

    def list_interfaces(self):
        from ingestion.capture.backends.base import InterfaceInfo

        return [InterfaceInfo(identifier="eth0", display_name="eth0", index=1)]

    def start(self, policy, output_dir: Path):
        from ingestion.capture.backends.base import CaptureHandle

        self.starts += 1
        output_dir.mkdir(parents=True, exist_ok=True)
        self.running = True
        return CaptureHandle(
            backend=self.backend_name,
            identifier="1",
            interface=policy.interface,
            output_dir=output_dir,
            file_prefix=policy.file_prefix,
        )

    def stop(self, handle, *, timeout: float = 10.0):
        was, self.running = self.running, False
        return was

    def is_running(self, handle):
        return self.running


class FakeRuntime:
    """Graph runtime double — counts runs, executes nothing."""

    def __init__(self):
        self.runs = 0

    def execute(self, state):
        self.runs += 1
        return state
