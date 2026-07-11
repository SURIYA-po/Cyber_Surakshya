"""
Redis connection management.

One shared async connection pool is created at app startup and reused by:
  - app.services.event_bus   (pub/sub — real-time event fan-out)
  - app.services.cache_service (cache-aside — stats caching)

Keeping a single module for the client means every other module just does
`from app.core.redis_client import get_redis` instead of managing its own
connection pool.
"""

import redis.asyncio as redis

from app.core.config import settings

# The pool itself — created once, reused for every command.
redis_pool: redis.ConnectionPool = redis.ConnectionPool.from_url(
    settings.REDIS_URL,
    decode_responses=True,
    max_connections=20,
)

# A client bound to the shared pool. redis.asyncio.Redis is safe to share
# across coroutines/requests — it borrows a connection per command.
redis_client: redis.Redis = redis.Redis(connection_pool=redis_pool)


def get_redis() -> redis.Redis:
    """FastAPI dependency / plain accessor for the shared Redis client."""
    return redis_client


async def ping_redis() -> bool:
    """Used by /health and the Agent Monitoring page's Redis status check."""
    try:
        return await redis_client.ping()
    except Exception:
        return False


async def close_redis() -> None:
    """Called on app shutdown to release the connection pool cleanly."""
    await redis_client.aclose()
    await redis_pool.disconnect()
