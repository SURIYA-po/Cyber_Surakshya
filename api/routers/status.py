"""Agent wiring, dashboard statistics, and memory diagnostics.
"""
from __future__ import annotations

import json
from datetime import datetime

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from api.projections import load_frontend_state_from_memory
from api.runtime import ensure_runtime, platform
from memory.models import MemoryQuery

router = APIRouter(tags=["platform"])


@router.get("/agents")
def get_agents():
    """The six pipeline agents and their live wiring state.

    Reported from what is actually registered on the runtime rather than a
    fixed list, so an agent that failed to initialize shows as OFFLINE instead
    of being quietly presented as healthy.
    """
    ensure_runtime()
    registered = set()
    if platform.runtime is not None:
        try:
            registered = {node.name for node in platform.runtime.builder.registered_nodes}
            if platform.runtime.builder.is_coordinated:
                registered.add("coordinator")
        except Exception:
            registered = set()

    def state(node: str) -> str:
        return "ONLINE" if node in registered else "OFFLINE"

    agents = [
        {"id": "agent-coordinator-01", "agent_name": "Coordinator Agent", "type": "Coordinator",
         "status": state("coordinator"), "version": "v1.0",
         "role": "Routes events, drains the work queue, detects stalled stages"},
        {"id": "agent-detect-01", "agent_name": "Detection Agent", "type": "Detection",
         "status": state("detection"), "version": "v1.2",
         "role": "Runs the IDS model over network flows"},
        {"id": "agent-analysis-01", "agent_name": "Analysis Agent", "type": "Analysis",
         "status": state("analysis"), "version": "v1.1",
         "role": "Produces structured reasoning from a detection"},
        {"id": "agent-decision-01", "agent_name": "Decision Agent", "type": "Decision",
         "status": state("decision"), "version": "v1.0",
         "role": "Chooses an action and whether a human must approve it"},
        {"id": "agent-response-01", "agent_name": "Response Agent", "type": "Response",
         "status": state("response"), "version": "v1.0",
         "role": "Authorises and executes containment; the only side-effecting node"},
        # Learning runs over history, not per event, so it is deliberately not
        # a pipeline node — see docs/learning_agent.md.
        {"id": "agent-learning-01", "agent_name": "Learning Agent", "type": "Learning",
         "status": "ONLINE" if platform.learning_agent is not None else "OFFLINE", "version": "v1.0",
         "role": "Measures outcomes and recommends improvements (runs on demand, not per event)"},
    ]
    return JSONResponse(content=agents)

@router.get("/agents/status")
def get_agents_status():
    ensure_runtime()
    agents = json.loads(get_agents().body)
    online = [a for a in agents if a["status"] == "ONLINE"]
    return JSONResponse(content={
        "status": "online" if len(online) == len(agents) else "degraded",
        "active_agents": len(online),
        "total_agents": len(agents),
        "ingestion_running": bool(platform.ingestion_service and platform.ingestion_service.is_running()),
    })


@router.get("/stats")
def get_stats():
    alerts, _, blocked_ips = load_frontend_state_from_memory()
    critical_cnt = len([a for a in alerts if str(a.get("severity")) == "CRITICAL"])
    high_cnt = len([a for a in alerts if str(a.get("severity")) == "HIGH"])

    trend_points = []
    for alert in alerts[:10]:
        created_at = alert.get("created_at")
        if not created_at:
            continue
        try:
            dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        except ValueError:
            continue
        trend_points.append({
            "label": dt.strftime("%a"),
            "value": 1,
        })

    trend_series = []
    if trend_points:
        bucket = {}
        for point in trend_points:
            bucket[point["label"]] = bucket.get(point["label"], 0) + point["value"]
        trend_series = [{"label": label, "value": bucket[label]} for label in ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"] if label in bucket]

    # `alerts` is the newest page, not the whole history, so len(alerts) is the
    # page size. It reported a permanent "Total Alerts: 100" while memory held
    # 999 detections. Count the collection instead.
    total_alerts = len(alerts)
    if platform.memory_provider is not None:
        try:
            total_alerts = platform.memory_provider.count("detections")
        except Exception as exc:
            print(f"[WARN] Could not count detections, falling back to page size: {exc}")

    # Derived from the same source as /agents rather than hardcoded, so a
    # newly added or failed agent is reflected here too.
    agents = json.loads(get_agents().body)
    online_agents = [a for a in agents if a["status"] == "ONLINE"]

    return JSONResponse(content={
        "total_alerts": total_alerts,
        "total_agents": len(agents),
        "online_agents": len(online_agents),
        "total_blocked_ips": len(blocked_ips),
        "average_confidence": round(sum(float(a.get("analysis", {}).get("confidence", 0)) for a in alerts if a.get("analysis")) / max(1, len(alerts)), 2),
        # Computed over the loaded page, not the full history — labelled so the
        # dashboard cannot present a sample as a total.
        "severity_breakdown": {
            "CRITICAL": critical_cnt,
            "HIGH": high_cnt,
            "MEDIUM": max(0, len(alerts) - critical_cnt - high_cnt)
        },
        "breakdown_sample_size": len(alerts),
        "trend": trend_series or [{"label": "Mon", "value": 0}, {"label": "Tue", "value": 0}, {"label": "Wed", "value": 0}, {"label": "Thu", "value": 0}, {"label": "Fri", "value": 0}, {"label": "Sat", "value": 0}, {"label": "Sun", "value": 0}],
    })

@router.get("/analyses")
def get_analyses():
    _, analyses, _ = load_frontend_state_from_memory()
    return JSONResponse(content=analyses)

@router.get("/analyses/{analysis_id}")
def get_analysis_by_id(analysis_id: str):
    _, analyses, _ = load_frontend_state_from_memory()
    for a in analyses:
        if str(a["id"]) == analysis_id:
            return JSONResponse(content=a)
    raise HTTPException(status_code=404, detail="Analysis not found")


@router.get("/debug/memory")
def debug_memory():
    """Return a summary of the shared memory provider and recent stored records."""
    ensure_runtime()
    if platform.memory_provider is None:
        raise HTTPException(status_code=503, detail="Memory provider not initialized")

    collections = ["detections", "analysis", "decisions", "threat_history"]
    summary = {}
    records = []

    for collection in collections:
        try:
            query = MemoryQuery(limit=10, order_by="created_at", descending=True)
            hits = platform.memory_provider.search(collection, query)
            summary[collection] = {
                "count": len(hits),
                "sample": [
                    {
                        "record_id": hit.record.record_id,
                        "record_type": hit.record.record_type,
                        "entity_id": hit.record.entity_id,
                        "tags": hit.record.tags,
                        "created_at": hit.record.created_at.isoformat(),
                        "content": hit.record.content,
                    }
                    for hit in hits
                ],
            }
        except Exception as exc:
            summary[collection] = {"count": 0, "error": str(exc)}

    try:
        recent = platform.memory_provider.search(
            "decisions",
            MemoryQuery(limit=5, order_by="created_at", descending=True),
        )
        records = [
            {
                "record_id": hit.record.record_id,
                "collection": hit.record.collection,
                "record_type": hit.record.record_type,
                "entity_id": hit.record.entity_id,
                "tags": hit.record.tags,
                "created_at": hit.record.created_at.isoformat(),
                "content": hit.record.content,
                "metadata": hit.record.metadata,
            }
            for hit in recent
        ]
    except Exception as exc:
        records = [{"error": str(exc)}]

    return {
        "provider": type(platform.memory_provider).__name__,
        "collections": summary,
        "recent_records": records,
    }
