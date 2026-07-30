"""Target entity of a recommended action."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ActionTarget(BaseModel):
    """Describes the entity on which a ResponseAgent should act.

    ``target_type`` names the class of entity (IP, HOST, FILE, etc.).
    ``target_value`` holds the concrete identifier (e.g. "192.168.1.5").
    ``asset_criticality`` is populated by an asset-inventory lookup;
    leave None until that component is built.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    target_type: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description='Entity class: "IP", "HOST", "FILE", "PROCESS", "USER", "ACCOUNT".',
    )
    target_value: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description="Concrete identifier: IP address, hostname, file path, etc.",
    )
    asset_criticality: str | None = Field(
        default=None,
        max_length=32,
        description='Optional asset criticality: "CRITICAL", "HIGH", "MEDIUM", "LOW".',
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Supplementary target context (e.g. geo-location, owner team).",
    )
