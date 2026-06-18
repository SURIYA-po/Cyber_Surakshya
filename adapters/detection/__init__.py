"""Detection adapter interfaces and implementations."""

from adapters.detection.base import DetectionAdapter
from adapters.detection.ids_adapter import IDSDetectionAdapter

__all__ = ["DetectionAdapter", "IDSDetectionAdapter"]
