"""Docker dumpcap backend — containerised capture for Linux hosts.

IMPORTANT PLATFORM CONSTRAINT

``--net=host`` only means "the machine's network" on a Linux host running the
Docker engine natively. On Docker Desktop (Windows/macOS) the engine runs
inside a Linux VM, so ``--net=host`` joins *that VM's* network namespace. A
capture started there does not fail — it succeeds against the wrong network,
seeing only container traffic while appearing perfectly healthy.

This backend therefore refuses to start when it detects Docker Desktop, rather
than silently tapping the wrong thing. Use LocalDumpcapBackend on those hosts.
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path

from ingestion.capture.backends.base import (
    CaptureBackend,
    CaptureBackendError,
    CaptureHandle,
    CaptureUnavailableError,
    InterfaceInfo,
)

logger = logging.getLogger(__name__)

# Docker Desktop reports these; a native Linux engine does not.
_DESKTOP_MARKERS = ("docker desktop", "docker.raw", "linuxkit")


class DockerDumpcapBackend(CaptureBackend):
    """Runs dumpcap inside a container sharing the host network namespace."""

    backend_name = "docker_dumpcap"

    def __init__(self, docker_policy, *, docker_path: str | None = None) -> None:
        self.policy      = docker_policy
        self.docker_path = docker_path or shutil.which("docker")

    # ── Availability ──────────────────────────────────────────────────────────

    def is_available(self) -> bool:
        return self.docker_path is not None and self._daemon_info() is not None

    def unavailable_reason(self) -> str:
        if self.docker_path is None:
            return "The docker CLI was not found on PATH."
        info = self._daemon_info()
        if info is None:
            return (
                "The Docker daemon is not reachable. Start Docker, or set "
                "capture.backend to 'local'."
            )
        if self.is_docker_desktop():
            return (
                "Docker Desktop detected. A container's --net=host joins the "
                "Docker VM's network namespace, not this machine's, so the "
                "capture would silently record the wrong network. Set "
                "capture.backend to 'local' for development on this host."
            )
        return "The docker backend is unavailable."

    def is_docker_desktop(self) -> bool:
        """True when the engine runs in a VM rather than natively."""
        info = self._daemon_info() or {}
        blob = " ".join(
            str(info.get(key, "")).lower()
            for key in ("OperatingSystem", "Name", "KernelVersion")
        )
        return any(marker in blob for marker in _DESKTOP_MARKERS)

    def _daemon_info(self) -> dict | None:
        if self.docker_path is None:
            return None
        try:
            result = subprocess.run(
                [self.docker_path, "info", "--format", "{{json .}}"],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode != 0:
                return None
            return json.loads(result.stdout or "{}")
        except Exception:
            return None

    # ── Interfaces ────────────────────────────────────────────────────────────

    def list_interfaces(self) -> list[InterfaceInfo]:
        """Enumerate interfaces as seen *inside* the capture container."""
        self._require_available()
        result = self._run(
            ["run", "--rm", "--net", self.policy.network_mode,
             "--cap-drop", "ALL", "--cap-add", "NET_RAW", "--cap-add", "NET_ADMIN",
             self.policy.image, "-D"],
            timeout=60,
        )
        interfaces: list[InterfaceInfo] = []
        for line in (result.stdout or "").splitlines():
            parts = line.strip().split(".", 1)
            if len(parts) != 2 or not parts[0].strip().isdigit():
                continue
            name = parts[1].strip().split()[0]
            interfaces.append(
                InterfaceInfo(
                    identifier=name, display_name=name, index=int(parts[0].strip())
                )
            )
        return interfaces

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self, policy, output_dir: Path) -> CaptureHandle:
        """Run the capture container with the minimum privileges dumpcap needs."""
        self._require_available()
        output_dir.mkdir(parents=True, exist_ok=True)

        args = self.build_dumpcap_args(policy, Path("/captures"))
        command = [
            "run", "--detach",
            "--name", self.policy.container_name,
            "--net", self.policy.network_mode,
            # Never --privileged. These two capabilities are exactly what
            # dumpcap needs, and it drops them after opening the socket.
            "--cap-drop", "ALL",
            *[arg for cap in self.policy.cap_add for arg in ("--cap-add", cap)],
            "--user", self.policy.user,
            "-v", f"{output_dir.resolve()}:/captures",
            "--restart", "no",
        ]
        if self.policy.read_only_rootfs:
            command += ["--read-only", "--tmpfs", "/tmp"]
        command += [self.policy.image, *args]

        logger.info(
            "docker_capture_starting",
            extra={
                "image":     self.policy.image,
                "interface": policy.interface,
                "snaplen":   policy.snaplen,
                "output_dir": str(output_dir),
            },
        )
        result = self._run(command, timeout=60)
        container_id = (result.stdout or "").strip()
        if not container_id:
            raise CaptureBackendError("docker run returned no container id.")

        return CaptureHandle(
            backend=self.backend_name,
            identifier=container_id,
            interface=policy.interface,
            output_dir=output_dir,
            file_prefix=policy.file_prefix,
        )

    def stop(self, handle: CaptureHandle, *, timeout: float = 10.0) -> bool:
        if not self.is_running(handle):
            self._run(["rm", "-f", handle.identifier], timeout=30, check=False)
            return False
        self._run(
            ["stop", "-t", str(int(timeout)), handle.identifier],
            timeout=timeout + 20,
        )
        self._run(["rm", "-f", handle.identifier], timeout=30, check=False)
        logger.info("docker_capture_stopped", extra={"container": handle.identifier[:12]})
        return True

    def is_running(self, handle: CaptureHandle) -> bool:
        result = self._run(
            ["inspect", "-f", "{{.State.Running}}", handle.identifier],
            timeout=20, check=False,
        )
        return (result.stdout or "").strip().lower() == "true"

    # ── Private ───────────────────────────────────────────────────────────────

    def _require_available(self) -> None:
        if not self.is_available() or self.is_docker_desktop():
            raise CaptureUnavailableError(self.unavailable_reason())

    def _run(self, args: list[str], *, timeout: float, check: bool = True):
        try:
            result = subprocess.run(
                [self.docker_path, *args],
                capture_output=True, text=True, timeout=timeout,
            )
        except Exception as exc:
            raise CaptureBackendError(f"docker {args[0]} failed: {exc}") from exc
        if check and result.returncode != 0:
            raise CaptureBackendError(
                f"docker {args[0]} failed ({result.returncode}): "
                f"{(result.stderr or '').strip()[:400]}"
            )
        return result
