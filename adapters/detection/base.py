"""Base interfaces for detection adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from cyber_surakshya.platform.schemas.detection_result import DetectionResult


class DetectionAdapter(ABC):
    """
    Common contract for detector integrations.

    Adapters bridge concrete detector output into platform schemas. They do
    not implement agents, workflow orchestration, or memory.
    """

    @abstractmethod
    def detect(self, flow_data: dict[str, Any]) -> DetectionResult:
        """Run detection for one raw flow record and return a schema object."""
