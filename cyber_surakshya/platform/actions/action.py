"""Composite Action model referenced by DecisionResult.

ResponseAgent reads this model exclusively. DecisionResult never
embeds an action enum directly — it always embeds an Action object
so ResponseAgent can dispatch to any integration without schema changes.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from cyber_surakshya.platform.actions.action_parameters import ActionParameters
from cyber_surakshya.platform.actions.action_target import ActionTarget
from cyber_surakshya.platform.actions.action_type import ActionType


class Action(BaseModel):
    """A fully-specified, executable action recommendation.

    ``action_type``  — the verb (what to do).
    ``target``       — the entity (what to act on).
    ``parameters``   — execution constraints (how to do it).
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    action_type: ActionType
    target: ActionTarget
    parameters: ActionParameters = Field(default_factory=ActionParameters)
