"""Learning agent domain exceptions."""
from __future__ import annotations


class LearningAgentError(Exception):
    """Base exception for all LearningAgent failures."""


class InsufficientHistoryError(LearningAgentError):
    """Raised when there is not enough history to analyse at all.

    Not raised during normal operation — an empty history produces an empty
    report rather than an error, because "we have learned nothing yet" is a
    valid and useful answer.
    """


class FeedbackStoreError(LearningAgentError):
    """Raised when analyst feedback cannot be written.

    Unlike most memory failures in the platform, this one is surfaced rather
    than swallowed: analyst feedback is the only ground truth the platform
    has, and silently losing it would corrupt every metric derived from it.
    """
