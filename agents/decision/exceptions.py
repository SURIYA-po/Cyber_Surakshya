"""Decision agent domain exceptions."""
from __future__ import annotations


class DecisionAgentError(Exception):
    """Base exception for all DecisionAgent failures."""


class NoPendingAnalysisError(DecisionAgentError):
    """Raised when there is no AnalysisResult awaiting a decision.

    This is treated as a skippable condition (not a hard failure) by
    DecisionAgent.__call__ — it returns a metadata-only state update.
    """


class PolicyEvaluationError(DecisionAgentError):
    """Raised when the decision engine cannot match any policy rule.

    Indicates that the rule table is incomplete (no catch-all rule) or
    the detection context contains values outside expected ranges.
    """


class MissingDetectionError(DecisionAgentError):
    """Raised when no DetectionResult matches an AnalysisResult.

    Signals broken referential integrity between analysis and detection
    results in the platform state.
    """


class MissingEventError(DecisionAgentError):
    """Raised when no SecurityEvent matches a DetectionResult.

    Signals broken referential integrity between detection results and
    source security events in the platform state.
    """
