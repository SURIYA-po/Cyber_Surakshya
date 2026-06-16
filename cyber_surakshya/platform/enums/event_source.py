"""Originating systems for security events."""

from enum import StrEnum


class EventSource(StrEnum):
    """Systems that can emit or ingest security events."""

    IDS = "ids"
    ZEEK = "zeek"
    FIREWALL = "firewall"
    SIEM = "siem"
    MANUAL = "manual"
    AGENT = "agent"
    PLATFORM = "platform"
