"""Parameters controlling how a ResponseAgent executes an action."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ActionParameters(BaseModel):
    """Execution parameters for a recommended action.

    ``duration_seconds`` constrains time-limited actions (e.g. rate-limit
    for 3 600 s).  ``scope`` restricts where the action applies.
    ``dry_run`` lets a ResponseAgent log without executing — useful for
    testing policy rules in production without side-effects.
    ``custom`` carries integration-specific fields (e.g. a CrowdStrike
    policy ID, a Wazuh rule ID, an AWS Security Group ID).
    """

    model_config = ConfigDict(extra="forbid")

    duration_seconds: int | None = Field(
        default=None,
        ge=1,
        description="How long (in seconds) to enforce a time-limited action.",
    )
    scope: str | None = Field(
        default=None,
        max_length=64,
        description='Execution scope: "perimeter", "internal", "endpoint", "cloud".',
    )
    dry_run: bool = Field(
        default=False,
        description="Log the action without executing it. Safe for policy testing.",
    )
    custom: dict[str, Any] = Field(
        default_factory=dict,
        description="Integration-specific parameters (CrowdStrike, Wazuh, SOAR, etc.).",
    )
