"""Coordinator agent domain exceptions."""
from __future__ import annotations


class CoordinatorAgentError(Exception):
    """Base exception for all CoordinatorAgent failures."""


class UnknownRouteTargetError(CoordinatorAgentError):
    """Raised when a route names a node the graph does not contain.

    Signals a wiring mistake between the coordinator's routing policy and the
    nodes registered on GraphBuilder — caught at build time rather than
    mid-run, where it would surface as a LangGraph KeyError.
    """


class IterationBudgetExceededError(CoordinatorAgentError):
    """Raised when a run exceeds its coordinator dispatch budget.

    Not raised into the graph during normal operation: the coordinator routes
    to END and records the anomaly instead. Reserved for callers that opt into
    strict mode.
    """
