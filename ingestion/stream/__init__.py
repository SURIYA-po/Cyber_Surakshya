"""Redis Streams transport between capture and the agent pipeline."""
from __future__ import annotations

from ingestion.stream.client import (
    RedisUnavailableError,
    connect,
    health,
    warn_on_insecure_posture,
)
from ingestion.stream.consumer import ConsumerStats, FlowConsumer, StreamFlow
from ingestion.stream.producer import FlowProducer, ProducerStats

__all__ = [
    "ConsumerStats",
    "FlowConsumer",
    "FlowProducer",
    "ProducerStats",
    "RedisUnavailableError",
    "StreamFlow",
    "connect",
    "health",
    "warn_on_insecure_posture",
]
