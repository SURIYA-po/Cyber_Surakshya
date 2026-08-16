"""Learning report schema.

LearningAgent produces one LearningReport per analysis run over historical
incidents. The report is a historical artifact, not run state — it is never
appended to PlatformSharedState.

Central design rule: every metric that depends on analyst ground truth carries
its own sample size and a ``sufficient_data`` flag. A confident wrong answer
looks exactly like a confident right one, so the platform cannot infer its own
false positives; only an analyst can supply them. A metric computed from two
labels must not be presentable as fact.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from cyber_surakshya.platform.audit.metadata import AuditMetadata
from cyber_surakshya.platform.identifiers.correlation import EntityId, is_valid_uuid


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _new_report_id() -> str:
    return str(uuid.uuid4())


def _new_feedback_id() -> str:
    return str(uuid.uuid4())


# ── Analyst feedback (the ground truth) ───────────────────────────────────────


class AnalystVerdict(str, Enum):
    """An analyst's ruling on what the platform concluded.

    CORRECT        — the platform got it right.
    INCORRECT      — the platform got it wrong (direction depends on the
                     detection: wrong on a threat is a false positive, wrong
                     on BENIGN is a false negative).
    FALSE_POSITIVE — explicitly benign traffic flagged as a threat.
    NEEDS_REVIEW   — inconclusive; excluded from accuracy arithmetic.
    ESCALATE       — real and more serious than the platform judged.
    """

    CORRECT        = "CORRECT"
    INCORRECT      = "INCORRECT"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    NEEDS_REVIEW   = "NEEDS_REVIEW"
    ESCALATE       = "ESCALATE"


# Verdicts that carry a usable ground-truth signal. NEEDS_REVIEW deliberately
# does not: counting "we don't know" as either right or wrong would corrupt
# every downstream metric.
CONCLUSIVE_VERDICTS: frozenset[AnalystVerdict] = frozenset({
    AnalystVerdict.CORRECT,
    AnalystVerdict.INCORRECT,
    AnalystVerdict.FALSE_POSITIVE,
    AnalystVerdict.ESCALATE,
})


class AnalystFeedback(BaseModel):
    """One analyst ruling on one incident.

    This is the platform's only source of truth about its own accuracy.
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra="forbid",
    )

    feedback_id:  EntityId = Field(default_factory=_new_feedback_id)
    detection_id: EntityId
    decision_id:  EntityId | None = None

    verdict:      AnalystVerdict
    analyst:      str = Field(..., min_length=1, max_length=256)
    notes:        str | None = Field(default=None, max_length=2048)

    # What the platform said, captured at feedback time so the label survives
    # even if the originating record is later pruned.
    predicted_label: str | None = Field(default=None, max_length=128)
    actual_label:    str | None = Field(
        default=None,
        max_length=128,
        description="The true label, when the analyst supplies one.",
    )

    metadata:    dict[str, Any] = Field(default_factory=dict)
    recorded_at: datetime       = Field(default_factory=_utc_now)

    @field_validator("feedback_id", "detection_id")
    @classmethod
    def check_uuid(cls, value: str) -> str:
        if not is_valid_uuid(value):
            raise ValueError(f"Invalid UUID: {value!r}")
        return str(value).lower()

    @field_validator("decision_id")
    @classmethod
    def check_optional_uuid(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not is_valid_uuid(value):
            raise ValueError(f"Invalid UUID: {value!r}")
        return str(value).lower()

    @field_validator("recorded_at")
    @classmethod
    def ensure_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @property
    def is_conclusive(self) -> bool:
        """True when this verdict can be used in accuracy arithmetic."""
        return self.verdict in CONCLUSIVE_VERDICTS


# ── Metrics ───────────────────────────────────────────────────────────────────


class MetricSummary(BaseModel):
    """One measured value, with the evidence base that produced it.

    ``value`` is None when ``sample_size`` is below the configured floor. A
    number computed from two observations is more dangerous than no number:
    it will be read as fact and acted upon.
    """

    model_config = ConfigDict(extra="forbid")

    name:            str = Field(..., min_length=1, max_length=128)
    value:           float | None = None
    unit:            str = Field(default="ratio", max_length=32)
    sample_size:     int = Field(default=0, ge=0)
    sufficient_data: bool = False
    detail:          str | None = Field(default=None, max_length=512)

    @model_validator(mode="after")
    def validate_confidence_coherence(self) -> MetricSummary:
        if self.sufficient_data and self.value is None:
            raise ValueError(
                f"Metric {self.name!r} claims sufficient data but has no value."
            )
        return self


# ── Patterns ──────────────────────────────────────────────────────────────────


class PatternType(str, Enum):
    """Recurring structures found across incident history."""

    REPEAT_ATTACKER           = "REPEAT_ATTACKER"
    FREQUENT_THREAT           = "FREQUENT_THREAT"
    REPEATED_RESPONSE_FAILURE = "REPEATED_RESPONSE_FAILURE"
    COMMON_ATTACK_PATH        = "COMMON_ATTACK_PATH"
    RECURRING_INCIDENT        = "RECURRING_INCIDENT"
    APPROVAL_BOTTLENECK       = "APPROVAL_BOTTLENECK"
    GUARD_FRICTION            = "GUARD_FRICTION"


class Pattern(BaseModel):
    """A recurring structure observed across incidents."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    pattern_type: PatternType
    summary:      str = Field(..., min_length=1, max_length=512)
    occurrences:  int = Field(..., ge=1)
    entities:     list[str] = Field(default_factory=list)
    first_seen:   datetime | None = None
    last_seen:    datetime | None = None
    confidence:   float = Field(default=1.0, ge=0.0, le=1.0)
    evidence:     dict[str, Any] = Field(default_factory=dict)


# ── Recommendations ───────────────────────────────────────────────────────────


class RecommendationType(str, Enum):
    """Improvements the platform proposes. None are applied automatically."""

    RAISE_CONFIDENCE_THRESHOLD    = "RAISE_CONFIDENCE_THRESHOLD"
    LOWER_CONFIDENCE_THRESHOLD    = "LOWER_CONFIDENCE_THRESHOLD"
    PREFER_LESS_DISRUPTIVE_ACTION = "PREFER_LESS_DISRUPTIVE_ACTION"
    ADD_CONTAINMENT_RULE          = "ADD_CONTAINMENT_RULE"
    REVIEW_POLICY                 = "REVIEW_POLICY"
    RETRAIN_MODEL                 = "RETRAIN_MODEL"
    REVIEW_EXECUTOR               = "REVIEW_EXECUTOR"
    TUNE_TRUST_TIER               = "TUNE_TRUST_TIER"
    COLLECT_MORE_FEEDBACK         = "COLLECT_MORE_FEEDBACK"


class RecommendationPriority(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


class Recommendation(BaseModel):
    """A proposed change. Advisory only — never applied by the platform.

    ``suggested_change`` describes what a human would do. LearningAgent does
    not retrain models, edit response_policy.yaml, or alter thresholds; a
    component that both concludes and acts on its conclusions has no review
    point.
    """

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    recommendation_type: RecommendationType
    priority:            RecommendationPriority
    summary:             str = Field(..., min_length=1, max_length=512)
    rationale:           str = Field(..., min_length=1, max_length=2048)
    suggested_change:    str = Field(..., min_length=1, max_length=1024)
    evidence:            dict[str, Any] = Field(default_factory=dict)
    supporting_metric:   str | None = Field(default=None, max_length=128)
    supporting_patterns: list[PatternType] = Field(default_factory=list)


# ── Report ────────────────────────────────────────────────────────────────────


class LearningReport(BaseModel):
    """Complete output of one LearningAgent run.

    ``feedback_coverage`` sits at the top deliberately: no consumer should
    read a ground-truth metric without first seeing how much of the history
    an analyst has actually labelled.
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra="forbid",
    )

    report_id: EntityId = Field(default_factory=_new_report_id)

    # ── Evidence base ─────────────────────────────────────────────────────────
    total_incidents:   int   = Field(default=0, ge=0)
    complete_incidents: int  = Field(default=0, ge=0)
    labeled_incidents: int   = Field(default=0, ge=0)
    feedback_coverage: float = Field(default=0.0, ge=0.0, le=1.0)

    window_start: datetime | None = None
    window_end:   datetime | None = None

    # ── Findings ──────────────────────────────────────────────────────────────
    metrics:         list[MetricSummary] = Field(default_factory=list)
    patterns:        list[Pattern]        = Field(default_factory=list)
    recommendations: list[Recommendation] = Field(default_factory=list)

    # ── Provenance ────────────────────────────────────────────────────────────
    analysis_duration_ms: float = Field(default=0.0, ge=0.0)
    min_sample_size:      int   = Field(default=10, ge=1)
    metadata:             dict[str, Any] = Field(default_factory=dict)
    generated_at:         datetime = Field(default_factory=_utc_now)
    audit:                AuditMetadata

    @field_validator("report_id")
    @classmethod
    def check_uuid(cls, value: str) -> str:
        if not is_valid_uuid(value):
            raise ValueError(f"Invalid UUID: {value!r}")
        return str(value).lower()

    @field_validator("generated_at", "window_start", "window_end")
    @classmethod
    def ensure_utc(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_counts(self) -> LearningReport:
        if self.labeled_incidents > self.total_incidents:
            raise ValueError(
                "labeled_incidents cannot exceed total_incidents."
            )
        if self.complete_incidents > self.total_incidents:
            raise ValueError(
                "complete_incidents cannot exceed total_incidents."
            )
        return self

    def metric(self, name: str) -> MetricSummary | None:
        """Return a metric by name, or None when it was not computed."""
        for summary in self.metrics:
            if summary.name == name:
                return summary
        return None
