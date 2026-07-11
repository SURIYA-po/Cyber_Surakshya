"""
Redis cache-aside layer.

The /stats/summary endpoint runs six aggregate queries against Postgres.
The dashboard polls it every 10s, and it's also read every time an alert
detail page or agent panel refreshes. Caching the computed result for a
few seconds means repeat reads in that window hit Redis instead of
re-scanning the alerts/analyses/blocked_ips tables.

Pattern: cache-aside (a.k.a. lazy loading)
  1. Try Redis first.
  2. On miss, compute from Postgres, then populate Redis with a TTL.
  3. On any write that changes the underlying data, explicitly delete the
     cache key so the next read is guaranteed fresh (see invalidate_stats_cache,
     called from the Coordinator and the direct CRUD routers).
"""

import json
from typing import Any, Optional

from app.core.config import settings
from app.core.redis_client import get_redis

STATS_CACHE_KEY = "cache:stats:summary"


async def get_cached_json(key: str) -> Optional[Any]:
    try:
        redis = get_redis()
        raw = await redis.get(key)
        return json.loads(raw) if raw is not None else None
    except Exception as exc:
        print(f"⚠️  Cache read failed ({key}): {exc}")
        return None


async def set_cached_json(key: str, value: Any, ttl_seconds: int) -> bool:
    try:
        redis = get_redis()
        await redis.set(key, json.dumps(value), ex=ttl_seconds)
        return True
    except Exception as exc:
        print(f"⚠️  Cache write failed ({key}): {exc}")
        return False


async def invalidate(key: str) -> bool:
    try:
        redis = get_redis()
        await redis.delete(key)
        return True
    except Exception as exc:
        print(f"⚠️  Cache invalidation failed ({key}): {exc}")
        return False


async def invalidate_stats_cache() -> None:
    """Called whenever alerts, analyses, or blocked_ips change."""
    await invalidate(STATS_CACHE_KEY)


async def get_or_set_stats(compute_fn) -> tuple[dict, str]:
    """
    Returns (payload, source) where source is "cache" or "database" —
    surfaced in the API response so the dashboard/demo can visibly show
    Redis caching at work.
    """
    cached = await get_cached_json(STATS_CACHE_KEY)
    if cached is not None:
        return cached, "cache"

    fresh = await compute_fn()
    await set_cached_json(STATS_CACHE_KEY, fresh, settings.STATS_CACHE_TTL_SECONDS)
    return fresh, "database"
