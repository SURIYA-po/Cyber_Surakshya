"""Redis connection construction and health checking.

Kept separate from the producer and consumer so both connect identically —
credentials, timeouts, and the security posture check cannot drift between
the two paths.
"""
from __future__ import annotations

import logging

from ingestion.exceptions import IngestionError

logger = logging.getLogger(__name__)

_CONNECT_TIMEOUT_SECONDS = 5


class RedisUnavailableError(IngestionError):
    """Raised when Redis cannot be reached or a write cannot be confirmed.

    Deliberately fatal by default. An ingestion layer that keeps running
    against a dead Redis discards flows silently, and a flow the platform
    never saw is an attack it never reported.
    """


def connect(policy, *, verify: bool = True, role: str | None = None):
    """Build a Redis client from a StreamPolicy.

    Args:
        verify: PING the server before returning, so a misconfiguration
            surfaces at startup rather than on the first captured packet.
        role: "producer" or "consumer", selecting per-role ACL credentials.
            Without this both would share one identity and the least-privilege
            split in docker/redis/users.acl would apply to nothing.

    Raises:
        RedisUnavailableError: the server is unreachable and the policy is
            fail-closed.
    """
    try:
        import redis
    except ImportError as exc:  # pragma: no cover - dependency is declared
        raise RedisUnavailableError(
            "The redis client is not installed. Add `redis>=5.0` to "
            "requirements.txt."
        ) from exc

    username, password = policy.credentials(role)
    client = redis.Redis.from_url(
        policy.url,
        username=username,
        password=password,
        decode_responses=True,
        socket_connect_timeout=_CONNECT_TIMEOUT_SECONDS,
        socket_timeout=_CONNECT_TIMEOUT_SECONDS,
        health_check_interval=30,
    )

    warn_on_insecure_posture(policy)

    if verify:
        try:
            client.ping()
        except Exception as exc:
            message = (
                f"Redis at {policy.url} is unreachable: {exc}. The ingestion "
                "layer will not start — accepting flows it cannot deliver "
                "would discard them silently."
            )
            if policy.fail_closed:
                raise RedisUnavailableError(message) from exc
            logger.error("redis_unreachable_continuing", extra={"error": str(exc)})

    return client


def warn_on_insecure_posture(policy) -> list[str]:
    """Log and return warnings about how Redis is exposed.

    Redis has no authentication by default and binds to every interface. The
    stream carries a complete record of who talked to whom on the monitored
    network, so an open instance leaks the very thing the platform exists to
    protect.
    """
    warnings: list[str] = []

    if not policy.is_authenticated:
        warnings.append(
            "Redis has no password configured. Set "
            f"{policy.password_env} and enable an ACL user — an unauthenticated "
            "instance exposes the full flow record to anyone who can reach it."
        )
    if not policy.is_loopback and not policy.uses_tls:
        warnings.append(
            f"Redis at {policy.url} is neither loopback nor TLS. Flow metadata "
            "would cross the network in plaintext; use rediss:// or keep Redis "
            "on an internal Docker network."
        )
    for warning in warnings:
        logger.warning("redis_insecure_posture", extra={"warning": warning})
    return warnings


def health(client, policy) -> dict:
    """Return a health snapshot for the control plane."""
    snapshot: dict = {
        "url":             policy.url,
        "stream_key":      policy.stream_key,
        "group":           policy.group,
        "authenticated":   policy.is_authenticated,
        "tls":             policy.uses_tls,
        "reachable":       False,
        "stream_length":   0,
        "max_length":      policy.max_length,
        "backlog_ratio":   0.0,
        "pending":         0,
        "consumers":       0,
        "dead_letter":     0,
    }
    try:
        client.ping()
        snapshot["reachable"] = True
    except Exception as exc:
        snapshot["error"] = str(exc)
        return snapshot

    try:
        length = int(client.xlen(policy.stream_key))
        snapshot["stream_length"] = length
        if policy.max_length > 0:
            snapshot["backlog_ratio"] = round(min(1.0, length / policy.max_length), 4)
        snapshot["dead_letter"] = int(client.xlen(policy.dead_letter_key))
    except Exception:
        pass

    try:
        pending = client.xpending(policy.stream_key, policy.group)
        if isinstance(pending, dict):
            snapshot["pending"] = int(pending.get("pending", 0) or 0)
            snapshot["consumers"] = len(pending.get("consumers") or [])
    except Exception:
        # No group yet is normal before the first consumer starts.
        pass

    return snapshot
