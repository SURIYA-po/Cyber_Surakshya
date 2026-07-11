"""
Redis Event Bus — Module 3 of the Cyber Surakshya architecture.

Channels
--------
simulated_detections   Dummy Surya (ML) detection events
simulated_analysis     Dummy LLM analysis events
simulated_response     Dummy Prakanda response/action events
dashboard_feed         Aggregate stream the frontend's SSE /feed consumes

Why Redis pub/sub here instead of the old DB-polling loop:
  - The workflow that GENERATES an incident (Coordinator, run from an HTTP
    request) and the workflow that STREAMS it to browsers (the SSE /feed
    endpoint, run from a totally different request/connection) are decoupled.
    Redis is the message bus between them, so alerts show up on the
    dashboard the instant they're created — not on the next poll tick.
  - It also means the design scales to multiple backend replicas: any
    instance can publish, any instance's /feed can pick it up.

Redis is a transport for real-time notification only. PostgreSQL remains
the single source of truth — nothing here is authoritative data.
"""

import json
from datetime import datetime, timezone
from typing import AsyncGenerator

from app.core.redis_client import get_redis


class EventBus:
    CHANNEL_DETECTIONS = "simulated_detections"
    CHANNEL_ANALYSIS = "simulated_analysis"
    CHANNEL_RESPONSE = "simulated_response"
    CHANNEL_DASHBOARD = "dashboard_feed"

    @staticmethod
    def _envelope(event_type: str, data: dict) -> str:
        return json.dumps({
            "type": event_type,
            "data": data,
            "ts": datetime.now(timezone.utc).isoformat(),
        })

    @classmethod
    async def publish(cls, channel: str, event_type: str, data: dict) -> bool:
        """
        Publish an event to a channel. Returns True/False instead of raising,
        so a Redis outage degrades the demo (no live push) rather than
        breaking the core workflow (alerts still land in Postgres either way).
        """
        try:
            redis = get_redis()
            message = cls._envelope(event_type, data)
            await redis.publish(channel, message)
            # Every event also fans out to the dashboard aggregate channel
            # unless it's already the dashboard channel itself.
            if channel != cls.CHANNEL_DASHBOARD:
                await redis.publish(cls.CHANNEL_DASHBOARD, message)
            return True
        except Exception as exc:
            print(f"⚠️  EventBus publish failed ({channel}): {exc}")
            return False

    @classmethod
    async def subscribe(cls, channel: str) -> AsyncGenerator[dict, None]:
        """
        Async generator yielding decoded {"type", "data", "ts"} messages
        published to `channel`. Used by the SSE /feed endpoint.
        """
        redis = get_redis()
        pubsub = redis.pubsub()
        try:
            await pubsub.subscribe(channel)
            async for message in pubsub.listen():
                if message["type"] != "message":
                    continue
                try:
                    yield json.loads(message["data"])
                except (TypeError, json.JSONDecodeError):
                    continue
        finally:
            await pubsub.unsubscribe(channel)
            await pubsub.aclose()
