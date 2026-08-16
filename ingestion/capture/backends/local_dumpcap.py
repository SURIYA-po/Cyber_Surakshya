"""Local dumpcap backend — runs the host's capture binary directly.

This is the backend that works on a Windows or macOS development machine,
where Docker Desktop's Linux VM cannot see the host's real network interfaces.

``dumpcap`` rather than Wireshark or tshark: it is the minimal capture engine
the other two shell out to, it is the only one designed to run unattended, and
it drops privileges immediately after opening the capture socket.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import signal
import subprocess
import time
from pathlib import Path

from ingestion.capture.backends.base import (
    CaptureBackend,
    CaptureBackendError,
    CaptureHandle,
    CaptureUnavailableError,
    InterfaceInfo,
)

logger = logging.getLogger(__name__)

# Standard install locations, checked when dumpcap is not on PATH.
_CANDIDATE_PATHS = [
    r"C:\Program Files\Wireshark\dumpcap.exe",
    r"C:\Program Files (x86)\Wireshark\dumpcap.exe",
    "/usr/bin/dumpcap",
    "/usr/local/bin/dumpcap",
    "/opt/homebrew/bin/dumpcap",
    "/Applications/Wireshark.app/Contents/MacOS/dumpcap",
]

# `1. \Device\NPF_{GUID} (Wi-Fi)` on Windows; `1. eth0` on Linux.
_INTERFACE_LINE = re.compile(r"^\s*(\d+)\.\s+(\S+)(?:\s+\((.*)\))?\s*$")


class LocalDumpcapBackend(CaptureBackend):
    """Runs dumpcap as a child process on this host."""

    backend_name = "local_dumpcap"

    def __init__(self, dumpcap_path: str | None = None) -> None:
        self.dumpcap_path = dumpcap_path or self._discover()

    # ── Availability ──────────────────────────────────────────────────────────

    @staticmethod
    def _discover() -> str | None:
        found = shutil.which("dumpcap")
        if found:
            return found
        for candidate in _CANDIDATE_PATHS:
            if Path(candidate).is_file():
                return candidate
        return None

    def is_available(self) -> bool:
        return self.dumpcap_path is not None

    def unavailable_reason(self) -> str:
        return (
            "dumpcap was not found on PATH or in a standard Wireshark install "
            "location. Install Wireshark (which bundles dumpcap and Npcap), or "
            "set capture.backend to 'docker' on a Linux host."
        )

    def version(self) -> str | None:
        """Return the dumpcap version string, or None when unavailable."""
        if not self.is_available():
            return None
        try:
            result = subprocess.run(
                [self.dumpcap_path, "-v"],
                capture_output=True, text=True, timeout=10,
            )
            first = (result.stdout or result.stderr).strip().splitlines()
            return first[0] if first else None
        except Exception as exc:
            logger.warning("dumpcap_version_failed", extra={"error": str(exc)})
            return None

    # ── Interfaces ────────────────────────────────────────────────────────────

    def list_interfaces(self) -> list[InterfaceInfo]:
        """Enumerate interfaces via ``dumpcap -D``."""
        self._require_available()
        try:
            result = subprocess.run(
                [self.dumpcap_path, "-D"],
                capture_output=True, text=True, timeout=30,
            )
        except Exception as exc:
            raise CaptureBackendError(f"Could not list interfaces: {exc}") from exc

        if result.returncode != 0:
            raise CaptureBackendError(
                f"dumpcap -D failed ({result.returncode}): "
                f"{(result.stderr or '').strip()[:300]}"
            )

        interfaces: list[InterfaceInfo] = []
        for line in (result.stdout or "").splitlines():
            match = _INTERFACE_LINE.match(line)
            if not match:
                continue
            index, identifier, display = match.groups()
            interfaces.append(
                InterfaceInfo(
                    identifier=identifier,
                    display_name=(display or identifier).strip(),
                    index=int(index),
                )
            )
        return interfaces

    def resolve_interface(self, requested: str) -> str:
        """Map a friendly name or index to what dumpcap expects.

        Accepts `"Wi-Fi"`, `"5"`, or a full `\\Device\\NPF_{...}` path. Resolving
        here rather than passing the string through means a typo fails at start
        with the list of valid options, instead of capturing nothing.
        """
        wanted = requested.strip()
        interfaces = self.list_interfaces()

        for info in interfaces:
            if wanted == info.identifier:
                return info.identifier
        if wanted.isdigit():
            for info in interfaces:
                if info.index == int(wanted):
                    return info.identifier
        for info in interfaces:
            if wanted.lower() == info.display_name.lower():
                return info.identifier
        for info in interfaces:
            if wanted.lower() in info.display_name.lower():
                return info.identifier

        available = ", ".join(f"{i.index}:{i.display_name}" for i in interfaces)
        raise CaptureBackendError(
            f"Interface {requested!r} does not match any capturable interface. "
            f"Available: {available}"
        )

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self, policy, output_dir: Path) -> CaptureHandle:
        """Launch dumpcap with a rotating ring buffer."""
        self._require_available()
        output_dir.mkdir(parents=True, exist_ok=True)

        resolved = self.resolve_interface(policy.interface)
        args = self.build_dumpcap_args(
            _WithInterface(policy, resolved), output_dir
        )
        command = [self.dumpcap_path, *args]

        logger.info(
            "local_capture_starting",
            extra={
                "interface":      resolved,
                "snaplen":        policy.snaplen,
                "rotate_seconds": policy.rotate_seconds,
                "retain_files":   policy.retain_files,
                "output_dir":     str(output_dir),
                "bpf_filter":     policy.bpf_filter or None,
            },
        )

        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                # New process group so stopping the capture never signals the
                # API server that spawned it.
                creationflags=(
                    subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
                ),
                start_new_session=(os.name != "nt"),
            )
        except Exception as exc:
            raise CaptureBackendError(f"Could not launch dumpcap: {exc}") from exc

        # dumpcap exits immediately on a bad interface or filter; catch that
        # here rather than reporting a healthy capture that is already dead.
        time.sleep(0.6)
        if process.poll() is not None:
            stderr = (process.stderr.read() or b"").decode("utf-8", "replace")
            raise CaptureBackendError(
                f"dumpcap exited immediately (code {process.returncode}): "
                f"{stderr.strip()[:400]}"
            )

        return CaptureHandle(
            backend=self.backend_name,
            identifier=str(process.pid),
            interface=resolved,
            output_dir=output_dir,
            file_prefix=policy.file_prefix,
        )

    def stop(self, handle: CaptureHandle, *, timeout: float = 10.0) -> bool:
        """Terminate the capture, allowing dumpcap to close its current file."""
        pid = int(handle.identifier)
        if not self.is_running(handle):
            return False

        try:
            if os.name == "nt":
                # CTRL_BREAK reaches the new process group and lets dumpcap
                # flush and close the in-progress pcap cleanly.
                os.kill(pid, signal.CTRL_BREAK_EVENT)
            else:
                os.kill(pid, signal.SIGTERM)
        except (ProcessLookupError, OSError) as exc:
            logger.warning(
                "local_capture_signal_failed",
                extra={"pid": pid, "error": str(exc)},
            )

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self._pid_alive(pid):
                logger.info("local_capture_stopped", extra={"pid": pid})
                return True
            time.sleep(0.2)

        logger.warning("local_capture_force_killing", extra={"pid": pid})
        try:
            os.kill(pid, signal.SIGKILL if os.name != "nt" else signal.SIGTERM)
        except (ProcessLookupError, OSError):
            pass
        return not self._pid_alive(pid)

    def is_running(self, handle: CaptureHandle) -> bool:
        try:
            return self._pid_alive(int(handle.identifier))
        except (TypeError, ValueError):
            return False

    # ── Private ───────────────────────────────────────────────────────────────

    def _require_available(self) -> None:
        if not self.is_available():
            raise CaptureUnavailableError(self.unavailable_reason())

    @staticmethod
    def _pid_alive(pid: int) -> bool:
        if os.name == "nt":
            result = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/NH"],
                capture_output=True, text=True,
            )
            return str(pid) in (result.stdout or "")
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True


class _WithInterface:
    """Policy view with the interface replaced by its resolved identifier."""

    def __init__(self, policy, interface: str) -> None:
        self._policy = policy
        self.interface = interface

    def __getattr__(self, name: str):
        return getattr(self._policy, name)
