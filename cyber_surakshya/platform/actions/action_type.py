"""Action type enumeration.

All supported action verbs live here. Adding a new integration
(CrowdStrike, Wazuh, SOAR, AWS Security Group, etc.) means adding
a new entry to this enum only. DecisionResult and ResponseAgent
never need to change.
"""
from __future__ import annotations

from enum import Enum


class ActionType(str, Enum):
    """Enumeration of all supported security response action verbs."""

    BLOCK_IP            = "BLOCK_IP"
    UNBLOCK_IP          = "UNBLOCK_IP"
    ISOLATE_HOST        = "ISOLATE_HOST"
    RELEASE_HOST        = "RELEASE_HOST"
    RATE_LIMIT          = "RATE_LIMIT"
    QUARANTINE_FILE     = "QUARANTINE_FILE"
    TERMINATE_PROCESS   = "TERMINATE_PROCESS"
    REVOKE_CREDENTIALS  = "REVOKE_CREDENTIALS"
    NOTIFY_SOC          = "NOTIFY_SOC"
    OPEN_TICKET         = "OPEN_TICKET"
    ENRICH_THREAT_INTEL = "ENRICH_THREAT_INTEL"
    LOG_ONLY            = "LOG_ONLY"
