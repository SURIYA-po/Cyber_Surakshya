"""Decision result schema.

DecisionAgent produces one DecisionResult per AnalysisResult.
ResponseAgent reads DecisionResult exclusively — it never reads
AnalysisResult or DetectionResult directly.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from cyber_surakshya.platform.actions.action import Action
from cyber_surakshya.platform.audit.metadata import AuditMetadata
from cyber_surakshya.platform.identifiers.correlation import (
    CorrelationId,
    EntityId,
    TraceId,
    is_valid_uuid,
)
from cyber_surakshya.platform.validation.rules import validate_confidence


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _new_decision_id() -> str:
    return str(uuid.uuid4())


# ── Enumerations ──────────────────────────────────────────────────────────────


class ApprovalStatus(str, Enum):
    """Lifecycle status of analyst or automated approval for a decision.

    PENDING       — awaiting human approval (requires_approval=True).
    APPROVED      — a human analyst approved the decision.
    REJECTED      — a human analyst rejected the decision.
    AUTO_APPROVED — policy engine approved without human review
                    (requires_approval=False).
    """

    PENDING       = "PENDING"
    APPROVED      = "APPROVED"
    REJECTED      = "REJECTED"
    AUTO_APPROVED = "AUTO_APPROVED"


class DecisionStatus(str, Enum):
    """Lifecycle state of a DecisionResult.

    CREATED             — freshly produced by DecisionAgent.
    WAITING_APPROVAL    — requires_approval=True; blocked on analyst review.
    READY_FOR_EXECUTION — approved (or auto-approved); ResponseAgent may act.
    EXECUTED            — ResponseAgent successfully executed the action.
    REJECTED            — analyst rejected; no action will be taken.
    FAILED              — ResponseAgent attempted execution but it failed.
    """

    CREATED             = "CREATED"
    WAITING_APPROVAL    = "WAITING_APPROVAL"
    READY_FOR_EXECUTION = "READY_FOR_EXECUTION"
    EXECUTED            = "EXECUTED"
    REJECTED            = "REJECTED"
    FAILED              = "FAILED"


class DecisionPriority(str, Enum):
    """Urgency level assigned to a decision by the policy engine."""

    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


# ── Model ─────────────────────────────────────────────────────────────────────


class DecisionResult(BaseModel):
    """Structured output from DecisionAgent.

    Contains the recommended action, priority, approval status, and
    full audit trail. Does NOT execute any action.

    ResponseAgent reads this schema exclusively. It never reads
    AnalysisResult or DetectionResult.
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra="forbid",
    )

    # ── Identity ──────────────────────────────────────────────────────────────
    decision_id:    EntityId      = Field(default_factory=_new_decision_id)
    analysis_id:    EntityId
    detection_id:   EntityId
    event_id:       EntityId
    correlation_id: CorrelationId
    trace_id:       TraceId

    # ── Decision payload ──────────────────────────────────────────────────────
    action:            Action
    priority:          DecisionPriority
    status:            DecisionStatus = DecisionStatus.CREATED

    # ── Approval ──────────────────────────────────────────────────────────────
    requires_approval: bool
    approval_status:   ApprovalStatus

    # ── Rationale ─────────────────────────────────────────────────────────────
    rationale:  str   = Field(..., min_length=1, max_length=2048)
    confidence: float = Field(..., ge=0.0, le=1.0)

    # ── Versioning ────────────────────────────────────────────────────────────
    policy_version:  str = Field(..., min_length=1, max_length=32)
    decision_engine: str = Field(..., min_length=1, max_length=128)
    engine_version:  str = Field(..., min_length=1, max_length=32)
    policy_name:     str = Field(..., min_length=1, max_length=128)

    # ── Extended performance audit ────────────────────────────────────────────
    decision_duration_ms: float = Field(..., ge=0.0)
    memory_hits:          int   = Field(..., ge=0)

    # ── Supplementary data ────────────────────────────────────────────────────
    metadata:   dict[str, Any] = Field(default_factory=dict)
    decided_at: datetime       = Field(default_factory=_utc_now)
    audit:      AuditMetadata

    # ── Validators ────────────────────────────────────────────────────────────

    @field_validator(
        "decision_id", "analysis_id", "detection_id",
        "event_id", "correlation_id", "trace_id",
    )
    @classmethod
    def check_uuid(cls, value: str) -> str:
        if not is_valid_uuid(value):
            raise ValueError(f"Invalid UUID: {value!r}")
        return str(value).lower()

    @field_validator("confidence")
    @classmethod
    def check_confidence(cls, value: float) -> float:
        return validate_confidence(value)

    @field_validator("decided_at")
    @classmethod
    def ensure_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_approval_lifecycle(self) -> DecisionResult:
        """Enforce coherence between requires_approval and approval_status."""
        if self.requires_approval and self.approval_status == ApprovalStatus.AUTO_APPROVED:
            raise ValueError(
                "requires_approval=True is incompatible with AUTO_APPROVED. "
                "Auto-approval is only valid for automated, non-gated decisions."
            )
        if not self.requires_approval and self.approval_status == ApprovalStatus.PENDING:
            raise ValueError(
                "requires_approval=False cannot have PENDING approval_status. "
                "Use AUTO_APPROVED for automated decisions."
            )
        return self
