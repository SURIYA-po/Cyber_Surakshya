"""Deterministic rule-based AI engine."""

from __future__ import annotations

from typing import Any

from ai_engine.base import AnalysisContext
from cyber_surakshya.platform.audit.metadata import AuditMetadata
from cyber_surakshya.platform.enums.detection_status import DetectionStatus
from cyber_surakshya.platform.schemas.analysis_result import (
    AnalysisEvidence,
    AnalysisResult,
)


class DeterministicRuleEngine:
    """
    Local deterministic reasoning engine.

    This engine performs no external calls and contains no state management,
    routing, threat intelligence, decision, or response logic.
    """

    engine_name = "deterministic_rule_engine"
    engine_version = "1.0.0"

    def analyze(self, context: AnalysisContext) -> AnalysisResult:
        detection = context.detection_result
        event = context.security_event
        evidence = self._build_evidence(context)
        uncertainty = self._build_uncertainty(context)

        summary = (
            f"Detection {detection.predicted_label} is {detection.status.value} "
            f"with {detection.confidence:.2%} confidence, "
            f"{detection.severity.label} severity, and risk score "
            f"{detection.risk_score.value:.2f}."
        )
        reasoning = (
            "Analysis mirrors the validated detection output and supporting "
            "event evidence. No escalation, alerting, threat intelligence, or "
            "response decision is applied in this component."
        )

        if detection.status == DetectionStatus.BENIGN:
            reasoning = (
                "The IDS classified the flow as benign. Analysis preserves the "
                "low-risk detection outcome for downstream decision components."
            )
        elif detection.status == DetectionStatus.INCONCLUSIVE:
            reasoning = (
                "The IDS produced a non-benign but low-confidence result. "
                "Downstream components should treat this as uncertain analysis "
                "rather than a response decision."
            )

        return AnalysisResult(
            event_id=event.event_id,
            detection_id=detection.detection_id,
            correlation_id=detection.correlation_id,
            trace_id=detection.trace_id,
            severity=detection.severity,
            risk_score=detection.risk_score,
            summary=summary,
            reasoning=reasoning,
            evidence=evidence,
            confidence=detection.confidence,
            uncertainty=uncertainty,
            metadata={
                "engine": self.engine_name,
                "engine_version": self.engine_version,
                "prior_analysis_count": context.prior_analysis_count,
            },
            audit=AuditMetadata(
                created_by=self.engine_name,
                updated_by=self.engine_name,
                source_system="analysis",
            ),
        )

    def _build_evidence(self, context: AnalysisContext) -> list[AnalysisEvidence]:
        detection = context.detection_result
        event = context.security_event
        evidence = [
            AnalysisEvidence(
                source="detection_result",
                name="predicted_label",
                value=detection.predicted_label,
                description="IDS model predicted label.",
            ),
            AnalysisEvidence(
                source="detection_result",
                name="status",
                value=detection.status.value,
                description="Validated detection outcome status.",
            ),
            AnalysisEvidence(
                source="detection_result",
                name="confidence",
                value=detection.confidence,
                description="IDS model confidence score.",
            ),
            AnalysisEvidence(
                source="detection_result",
                name="risk_score",
                value=detection.risk_score.value,
                description="Detection risk score mirrored into analysis.",
            ),
        ]

        for label, probability in self._top_probabilities(detection.probabilities):
            evidence.append(
                AnalysisEvidence(
                    source="detection_result",
                    name=f"probability:{label}",
                    value=probability,
                    description="Class probability from IDS output.",
                )
            )

        for name, value in self._selected_features(detection.feature_snapshot).items():
            evidence.append(
                AnalysisEvidence(
                    source="feature_snapshot",
                    name=name,
                    value=value,
                    description="Relevant numeric flow feature captured by detection.",
                )
            )

        if not detection.feature_snapshot and event.features:
            for name, value in self._selected_features(event.features).items():
                evidence.append(
                    AnalysisEvidence(
                        source="security_event.features",
                        name=name,
                        value=value,
                        description="Relevant numeric flow feature from source event.",
                    )
                )

        return evidence

    def _build_uncertainty(self, context: AnalysisContext) -> list[str]:
        detection = context.detection_result
        event = context.security_event
        uncertainty: list[str] = []

        if detection.status == DetectionStatus.INCONCLUSIVE:
            uncertainty.append("Detection status is inconclusive.")
        if detection.confidence < 0.6:
            uncertainty.append("Detection confidence is below 0.60.")
        if not detection.probabilities:
            uncertainty.append("Class probability map is unavailable.")
        if not detection.feature_snapshot and not event.features:
            uncertainty.append("Source event features are unavailable.")

        return uncertainty

    def _top_probabilities(self, probabilities: dict[str, float]) -> list[tuple[str, float]]:
        return sorted(probabilities.items(), key=lambda item: item[1], reverse=True)[:3]

    def _selected_features(self, features: dict[str, Any]) -> dict[str, float]:
        selected: dict[str, float] = {}
        for name in sorted(features)[:8]:
            value = features[name]
            if isinstance(value, bool):
                continue
            if isinstance(value, int | float):
                selected[name] = float(value)
        return selected
