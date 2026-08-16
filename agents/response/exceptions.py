"""Response agent domain exceptions."""
from __future__ import annotations


class ResponseAgentError(Exception):
    """Base exception for all ResponseAgent failures."""


class NoPendingDecisionError(ResponseAgentError):
    """Raised when no DecisionResult is awaiting a response.

    Treated as a skippable condition (not a hard failure) by
    ResponseAgent.__call__ — it returns a metadata-only state update.
    """


class ExecutionFailedError(ResponseAgentError):
    """Raised when an executor could not complete an action.

    Carries the attempt history so the failure is auditable rather than
    collapsed to a single message.
    """

    def __init__(self, message: str, *, attempts: int = 0) -> None:
        super().__init__(message)
        self.attempts = attempts


class RevertFailedError(ResponseAgentError):
    """Raised when a rollback could not be completed.

    Distinct from ExecutionFailedError because a failed revert leaves a
    containment in force that the platform believes it has released — an
    operator must be told, not just a retry scheduled.
    """
