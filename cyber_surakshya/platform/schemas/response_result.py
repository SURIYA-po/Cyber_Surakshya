"""Response result schema.

ResponseAgent produces one ResponseResult per DecisionResult.
This is the only platform record that describes a real-world side-effect.

ResponseResult is append-only. DecisionResult is never mutated — a
decision's effective lifecycle is a projection obtained by joining
response_results on decision_id. See docs/response_agent.md.
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


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _new_response_id() -> str:
    return str(uuid.uuid4())


# ── Enumerations ──────────────────────────────────────────────────────────────


class ResponseStatus(str, Enum):
    """Terminal or resumable outcome of a response execution attempt.

    EXECUTED          — an executor confirmed the side-effect.
    DRY_RUN           — simulated only; no side-effect was produced.
    AWAITING_APPROVAL — an approval or safety gate deferred it; resumable.
    BLOCKED_BY_GUARD  — the safety gate denied it. Terminal.
    DOWNGRADED        — the guard substituted a less destructive action,
                        and the substitute executed successfully.
    DEDUPLICATED      — an identical action already ran inside the
                        idempotency window; the prior response is referenced.
    NO_OP             — nothing to execute (LOG_ONLY, or a rejected decision).
    FAILED            — the executor raised or timed out after all retries.
    REVERTED          — this response rolled back a prior response.
    """

    EXECUTED          = "EXECUTED"
    DRY_RUN           = "DRY_RUN"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    BLOCKED_BY_GUARD  = "BLOCKED_BY_GUARD"
    DOWNGRADED        = "DOWNGRADED"
    DEDUPLICATED      = "DEDUPLICATED"
    NO_OP             = "NO_OP"
    FAILED            = "FAILED"
    REVERTED          = "REVERTED"


class GuardVerdict(str, Enum):
    """Authorisation outcome produced by ActionGuard.

    Recorded on every ResponseResult — including ALLOW — so that each
    execution carries a traceable authorisation decision.

    ALLOW            — execute the decided action as-is.
    ALLOW_DRY_RUN    — execute in simulation only.
    REQUIRE_APPROVAL — a human analyst must approve before execution.
    DOWNGRADE        — replace with a less destructive substitute action.
    DENY             — do not execute. Terminal.
    """

    ALLOW            = "ALLOW"
    ALLOW_DRY_RUN    = "ALLOW_DRY_RUN"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    DOWNGRADE        = "DOWNGRADE"
    DENY             = "DENY"


class EngineTrustTier(str, Enum):
    """Trust level assigned to the decision engine that produced an action.

    The response layer must stay safe when DecisionAgent is switched from
    a bounded rule table to an unbounded language model. Tier is resolved
    from DecisionResult.decision_engine via configuration.

    DETERMINISTIC   — bounded rule-table engine; destructive actions allowed.
    AI_SUPERVISED   — LLM engine; destructive actions always require a human.
    AI_AUTONOMOUS   — LLM engine explicitly trusted by the operator (opt-in).
    UNKNOWN         — unregistered engine. Fail-closed: always downgraded.
    """

    DETERMINISTIC = "DETERMINISTIC"
    AI_SUPERVISED = "AI_SUPERVISED"
    AI_AUTONOMOUS = "AI_AUTONOMOUS"
    UNKNOWN       = "UNKNOWN"


# ── Execution attempt ─────────────────────────────────────────────────────────


class ExecutionAttempt(BaseModel):
    """One executor invocation, successful or not.

    Retries append additional attempts, so the full execution history of a
    response is preserved for audit rather than collapsed to a final state.
    """

    model_config = ConfigDict(extra="forbid")

    attempt_number: int      = Field(..., ge=1)
    succeeded:      bool
    started_at:     datetime = Field(default_factory=_utc_now)
    duration_ms:    float    = Field(..., ge=0.0)
    error_type:     str | None = Field(default=None, max_length=128)
    error_message:  str | None = Field(default=None, max_length=1024)

    @field_validator("started_at")
    @classmethod
    def ensure_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_error_coherence(self) -> ExecutionAttempt:
        if self.succeeded and (self.error_type or self.error_message):
            raise ValueError("A successful attempt must not carry error details.")
        if not self.succeeded and not self.error_type:
            raise ValueError("A failed attempt must record an error_type.")
        return self


# ── Model ─────────────────────────────────────────────────────────────────────


class ResponseResult(BaseModel):
    """Structured output from ResponseAgent.

    Records what was decided, what was authorised, what actually ran, and
    what it produced in the outside world.

    ``action``          — the action that was executed (post-guard).
    ``original_action`` — the action as decided by DecisionAgent. Differs
                          from ``action`` only when the guard downgraded it.
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra="forbid",
    )

    # ── Identity & lineage ────────────────────────────────────────────────────
    response_id:    EntityId = Field(default_factory=_new_response_id)
    decision_id:    EntityId
    correlation_id: CorrelationId
    trace_id:       TraceId

    # ── Action ────────────────────────────────────────────────────────────────
    action:          Action
    original_action: Action
    status:          ResponseStatus

    # ── Authorisation trail ───────────────────────────────────────────────────
    guard_verdict:     GuardVerdict
    guard_rule:        str = Field(..., min_length=1, max_length=128)
    guard_reason:      str = Field(..., min_length=1, max_length=2048)
    engine_trust_tier: EngineTrustTier
    decision_engine:   str = Field(..., min_length=1, max_length=128)

    # ── Execution ─────────────────────────────────────────────────────────────
    executor_name:    str | None = Field(default=None, max_length=128)
    executor_version: str | None = Field(default=None, max_length=32)
    idempotency_key:  str        = Field(..., min_length=1, max_length=128)
    attempts:         list[ExecutionAttempt] = Field(default_factory=list)

    # ── Outcome references ────────────────────────────────────────────────────
    external_reference:  str | None = Field(
        default=None,
        max_length=512,
        description="Identifier returned by the target system (firewall rule ID, "
                    "EDR containment ID, ticket key).",
    )
    revert_token: str | None = Field(
        default=None,
        max_length=512,
        description="Opaque token allowing this response to be rolled back.",
    )
    reverts_response_id: EntityId | None = Field(
        default=None,
        description="Set when this response rolls back a prior response.",
    )
    duplicate_of_response_id: EntityId | None = Field(
        default=None,
        description="Set when status is DEDUPLICATED; points at the original.",
    )

    # ── Timing ────────────────────────────────────────────────────────────────
    response_duration_ms: float    = Field(..., ge=0.0)
    executed_at:          datetime = Field(default_factory=_utc_now)
    expires_at:           datetime | None = Field(
        default=None,
        description="When a time-limited action (rate limit, temporary block) lapses.",
    )

    # ── Supplementary data ────────────────────────────────────────────────────
    metadata: dict[str, Any] = Field(default_factory=dict)
    audit:    AuditMetadata

    # ── Validators ────────────────────────────────────────────────────────────

    @field_validator("response_id", "decision_id", "correlation_id", "trace_id")
    @classmethod
    def check_uuid(cls, value: str) -> str:
        if not is_valid_uuid(value):
            raise ValueError(f"Invalid UUID: {value!r}")
        return str(value).lower()

    @field_validator("reverts_response_id", "duplicate_of_response_id")
    @classmethod
    def check_optional_uuid(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not is_valid_uuid(value):
            raise ValueError(f"Invalid UUID: {value!r}")
        return str(value).lower()

    @field_validator("executed_at", "expires_at")
    @classmethod
    def ensure_utc(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_execution_coherence(self) -> ResponseResult:
        """Enforce that the recorded outcome is internally consistent.

        These invariants make an impossible ResponseResult unconstructible,
        so audit consumers can trust the record without cross-checking.
        """
        executed_states = {
            ResponseStatus.EXECUTED,
            ResponseStatus.DOWNGRADED,
            ResponseStatus.REVERTED,
        }
        if self.status in executed_states and not self.executor_name:
            raise ValueError(
                f"status={self.status.value} requires executor_name to be set."
            )
        if self.status is ResponseStatus.BLOCKED_BY_GUARD:
            if self.attempts:
                raise ValueError(
                    "BLOCKED_BY_GUARD must not record execution attempts — "
                    "the action never reached an executor."
                )
            if self.guard_verdict is not GuardVerdict.DENY:
                raise ValueError(
                    "BLOCKED_BY_GUARD requires guard_verdict=DENY."
                )
        if self.status is ResponseStatus.AWAITING_APPROVAL and self.attempts:
            raise ValueError(
                "AWAITING_APPROVAL must not record execution attempts."
            )
        if self.status is ResponseStatus.DOWNGRADED:
            if self.guard_verdict is not GuardVerdict.DOWNGRADE:
                raise ValueError(
                    "DOWNGRADED requires guard_verdict=DOWNGRADE."
                )
            if self.action == self.original_action:
                raise ValueError(
                    "DOWNGRADED requires action to differ from original_action."
                )
        if self.status is ResponseStatus.DEDUPLICATED and not self.duplicate_of_response_id:
            raise ValueError(
                "DEDUPLICATED requires duplicate_of_response_id to be set."
            )
        if self.status is ResponseStatus.REVERTED and not self.reverts_response_id:
            raise ValueError(
                "REVERTED requires reverts_response_id to be set."
            )
        return self
