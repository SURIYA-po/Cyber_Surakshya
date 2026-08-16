"""Learning agent package.

Five modules, wired so analyst feedback feeds the metrics rather than
trailing them — see docs/learning_agent.md.
"""
from __future__ import annotations

from agents.learning.exceptions import (
    FeedbackStoreError,
    InsufficientHistoryError,
    LearningAgentError,
)
from agents.learning.feedback import FeedbackRecorder
from agents.learning.learning_agent import REPORTS_COLLECTION, LearningAgent
from agents.learning.metrics_engine import DEFAULT_MIN_SAMPLE_SIZE, MetricsEngine
from agents.learning.outcome_collector import (
    FEEDBACK_COLLECTION,
    IncidentHistory,
    OutcomeCollector,
)
from agents.learning.pattern_discovery import PatternDiscovery, PatternThresholds
from agents.learning.recommendation_engine import (
    RecommendationEngine,
    RecommendationThresholds,
)

__all__ = [
    "DEFAULT_MIN_SAMPLE_SIZE",
    "FEEDBACK_COLLECTION",
    "REPORTS_COLLECTION",
    "FeedbackRecorder",
    "FeedbackStoreError",
    "IncidentHistory",
    "InsufficientHistoryError",
    "LearningAgent",
    "LearningAgentError",
    "MetricsEngine",
    "OutcomeCollector",
    "PatternDiscovery",
    "PatternThresholds",
    "RecommendationEngine",
    "RecommendationThresholds",
]
