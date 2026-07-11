from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.database import get_db
from app.models.alert import Alert
from app.models.blocked_ip import BlockedIP
from app.models.agent import Agent
from app.models.analysis import Analysis
from app.services.cache_service import get_or_set_stats

router = APIRouter(prefix="/stats", tags=["Statistics"])


@router.get("")
async def get_stats(db: AsyncSession = Depends(get_db)):
    """
    Returns dashboard summary statistics.
    Used by the Dashboard cards on the frontend.

    Cached in Redis for STATS_CACHE_TTL_SECONDS (cache-aside pattern): the
    dashboard polls this every 10s, so most reads are served from Redis
    instead of re-running six aggregate queries against Postgres. The
    Coordinator explicitly invalidates the cache key whenever new data is
    written, so numbers never look stale for longer than one write.

    The response includes a "_cache_source" field ("cache" | "database") —
    kept as an underscore-prefixed field purely so it's visible during a
    demo without needing to change any frontend model.
    """
    payload, source = await get_or_set_stats(lambda: _compute_stats(db))
    return {**payload, "_cache_source": source}


async def _compute_stats(db: AsyncSession) -> dict:
    # Total alerts
    total_alerts = (await db.execute(
        select(func.count(Alert.id))
    )).scalar_one()

    # Alerts by severity
    severity_rows = (await db.execute(
        select(Alert.severity, func.count(Alert.id))
        .group_by(Alert.severity)
    )).all()
    severity_breakdown = {row[0]: row[1] for row in severity_rows}

    # Alerts by status
    status_rows = (await db.execute(
        select(Alert.status, func.count(Alert.id))
        .group_by(Alert.status)
    )).all()
    status_breakdown = {row[0]: row[1] for row in status_rows}

    # Blocked IPs count
    total_blocked = (await db.execute(
        select(func.count(BlockedIP.id))
    )).scalar_one()

    # Agent count and status
    agent_rows = (await db.execute(
        select(Agent.status, func.count(Agent.id))
        .group_by(Agent.status)
    )).all()
    agent_status = {row[0]: row[1] for row in agent_rows}
    total_agents = sum(agent_status.values())
    online_agents = agent_status.get("ONLINE", 0)

    # Average confidence from analyses
    avg_confidence = (await db.execute(
        select(func.avg(Analysis.confidence))
    )).scalar_one()

    # Attack type breakdown
    attack_rows = (await db.execute(
        select(Alert.attack_type, func.count(Alert.id))
        .group_by(Alert.attack_type)
        .order_by(func.count(Alert.id).desc())
    )).all()
    attack_breakdown = {row[0]: row[1] for row in attack_rows}

    return {
        "total_alerts": total_alerts,
        "total_blocked_ips": total_blocked,
        "total_agents": total_agents,
        "online_agents": online_agents,
        "average_confidence": round(avg_confidence or 0, 2),
        "severity_breakdown": severity_breakdown,
        "status_breakdown": status_breakdown,
        "attack_type_breakdown": attack_breakdown,
        "agent_status": agent_status
    }
