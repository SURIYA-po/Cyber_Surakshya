"""Decision engine interface, context, and draft output models.

Mirrors ai_engine/base.py exactly. DecisionAgent depends on the
DecisionEngine Protocol only — concrete implementations
(DeterministicDecisionEngine, OllamaDecisionEngine, etc.) are
injected at startup without changing the agent.
"""
from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from cyber_surakshya.platform.actions.action import Action
from cyber_surakshya.platform.schemas.analysis_result import AnalysisResult
from cyber_surakshya.platform.schemas.decision_result import (
    ApprovalStatus,
    DecisionPriority,
)
from cyber_surakshya.platform.schemas.detection_result import DetectionResult
from cyber_surakshya.platform.schemas.security_event import SecurityEvent
from memory.models import MemorySearchResult


# ── Input context ─────────────────────────────────────────────────────────────


class DecisionContext(BaseModel):
    """Input context supplied to all decision engines.

    Mirrors AnalysisContext. Groups every input so engine method
    signatures never change when new contextual fields are added.

    ``historical_records`` — prior threat events from MemoryProvider
                             for the same entity (source IP, host, etc.).
    ``organization_policy``— key-value policy overrides (e.g. escalation
                             thresholds). Loaded from config at startup.
    ``asset_metadata``     — asset-inventory context (criticality, owner).
                             Populated by an AssetInventory component (future).
    """

    model_config = ConfigDict(extra="forbid")

    security_event:       SecurityEvent
    detection_result:     DetectionResult
    analysis_result:      AnalysisResult
    historical_records:   list[MemorySearchResult] = Field(default_factory=list)
    organization_policy:  dict[str, Any]           = Field(default_factory=dict)
    asset_metadata:       dict[str, Any]           = Field(default_factory=dict)
    prior_decision_count: int                      = Field(default=0, ge=0)


# ── Draft output (pre-ID linkage) ─────────────────────────────────────────────


class DecisionDraft(BaseModel):
    """Intermediate output from a decision engine, before state linkage.

    DecisionAgent receives a DecisionDraft, attaches correlation IDs,
    timing, and audit metadata, then produces the final DecisionResult.
    """

    model_config = ConfigDict(extra="forbid")

    action:            Action
    priority:          DecisionPriority
    requires_approval: bool
    approval_status:   ApprovalStatus
    rationale:         str   = Field(..., min_length=1, max_length=2048)
    confidence:        float = Field(..., ge=0.0, le=1.0)
    policy_name:       str   = Field(..., min_length=1, max_length=128)
    memory_hits:       int   = Field(default=0, ge=0)


# ── Engine Protocol ───────────────────────────────────────────────────────────


@runtime_checkable
class DecisionEngine(Protocol):
    """Generic interface implemented by all decision backends.

    Implementations (injected at startup — DecisionAgent never imports them):
      - DeterministicDecisionEngine  (rule-based, no LLM)  — production default
      - OllamaDecisionEngine         (local LLM)           — future
      - ClaudeDecisionEngine         (cloud LLM)           — future
      - GPTDecisionEngine            (OpenAI)              — future

    No agent changes are required to swap implementations.
    """

    engine_name:    str
    engine_version: str
    policy_version: str

    def make_decision(self, context: DecisionContext) -> DecisionDraft:
        """Evaluate context and return a decision draft."""
        ...
