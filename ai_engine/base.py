"""Generic AI engine interface for analysis reasoning."""

from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from cyber_surakshya.platform.schemas.analysis_result import AnalysisResult
from cyber_surakshya.platform.schemas.detection_result import DetectionResult
from cyber_surakshya.platform.schemas.security_event import SecurityEvent


class AnalysisContext(BaseModel):
    """Input context supplied to AI engines for structured analysis."""

    model_config = ConfigDict(extra="forbid")

    security_event: SecurityEvent
    detection_result: DetectionResult
    prior_analysis_count: int = Field(default=0, ge=0)


class AIEngine(Protocol):
    """Generic interface implemented by all reasoning backends."""

    def analyze(self, context: AnalysisContext) -> AnalysisResult:
        """Produce structured analysis for a detection context."""
