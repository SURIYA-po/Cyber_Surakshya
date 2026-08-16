"""Public endpoints: liveness and the real-time activity feed.

No API key required. /health must be reachable by a load balancer, and
/feed is the dashboard's log stream.
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import pandas as pd
from fastapi import APIRouter
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse

from api.runtime import ARTIFACT_DIR, ensure_runtime, platform
from inference import load_manifest, predict
from observability import event_log, render_platform_metrics

router = APIRouter(tags=["platform"])


_FEED_KEEPALIVE_SECONDS = 15.0
_FEED_POLL_SECONDS = 0.5


@router.get("/feed")
async def get_feed():
    """Server-Sent Events stream of REAL platform activity.

    Every event here is an actual log record emitted by an agent, adapter, the
    ingestion worker, or the graph runtime -- drained from
    `observability.event_log`, which a logging handler fills.

    This endpoint previously emitted randomly chosen strings from a hardcoded
    list, including "Cross-referencing IOCs..." and "Updating behavioral
    baseline...", neither of which corresponds to anything the platform does.
    Anyone watching the dashboard was shown a system that did not exist.
    """
    async def event_generator():
        # Start from the current end of the buffer: a new subscriber wants to
        # watch what happens next, not replay history it has already missed.
        cursor = event_log.latest_seq()
        last_output = time.monotonic()

        yield f"event: connected\ndata: {json.dumps({'cursor': cursor})}\n\n"

        while True:
            await asyncio.sleep(_FEED_POLL_SECONDS)

            events = event_log.since(cursor)
            for event in events:
                cursor = event.seq
                yield f"event: agent_log\ndata: {json.dumps(event.as_dict())}\n\n"
                last_output = time.monotonic()

            if not events and time.monotonic() - last_output > _FEED_KEEPALIVE_SECONDS:
                # A comment, not an event. The dashboard's EventSource ignores
                # it; the connection survives.
                yield ": keep-alive\n\n"
                last_output = time.monotonic()

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            # Tells nginx not to buffer the stream, which otherwise delivers
            # the whole feed only when the connection closes.
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/metrics")
def get_metrics():
    """Prometheus scrape endpoint.

    Public, alongside /health: a scraper that needs a credential is a scraper
    that silently stops working when the credential rotates, and these are
    counters, not incident data — no IPs, labels, or payloads.

    Everything here already existed as structured counters inside the
    ingestion and response layers; they were only reachable through a JSON
    blob no scraper understands.
    """
    ensure_runtime()
    body = render_platform_metrics(platform, event_log=event_log)
    return PlainTextResponse(
        content=body,
        # The version suffix is what tells Prometheus this is the text
        # exposition format rather than an arbitrary text/plain document.
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@router.get("/feed/recent")
def get_recent_events(limit: int = 50):
    """The last N real platform events, for a dashboard that just loaded.

    Public alongside /feed, and useful for debugging without holding a stream
    open.
    """
    return {"events": [event.as_dict() for event in event_log.recent(limit)]}


# Health is public
@router.get("/health")
def health():
    """Report whether the platform can actually detect, not merely whether it booted.

    `platform.runtime is not None` was the entire check. It stayed true when the model
    artifacts were missing, because inference substituted a stub that returned
    BENIGN at confidence 1.0 for every flow — so a blind IDS reported itself
    healthy. Artifact loading now fails closed, and this endpoint proves the
    detector by scoring one flow end to end.
    """
    detail: dict[str, Any] = {
        "runtime": platform.runtime is not None,
        "artifacts_loaded": platform.artifacts is not None,
        "detector": "unknown",
        "anomaly_layer": "unknown",
    }

    if platform.artifacts is None or platform.runtime is None:
        detail["detector"] = "unavailable"
        detail["reason"] = (
            "Model artifacts failed to load. Detection is disabled — see the "
            "server log for the ArtifactError. Run `python train.py` or set "
            "ARTIFACT_DIR."
        )
        return JSONResponse(status_code=503, content={"status": "unavailable", **detail})

    detail["anomaly_layer"] = (
        "active" if getattr(platform.artifacts, "anomaly_ready", False) else "unavailable"
    )
    detail["classes"] = [str(c) for c in getattr(platform.artifacts.le, "classes_", [])]
    detail["feature_count"] = len(platform.artifacts.feature_cols)

    # Which model is serving, and its weakest class. An operator should not
    # have to read the training report to find out that the detector in
    # production catches 8% of one attack family.
    detail["model"] = {"type": type(platform.artifacts.model).__name__}
    manifest = load_manifest(ARTIFACT_DIR)
    if manifest:
        served = manifest.get("served_model_name")
        served_metrics = (manifest.get("metrics") or {}).get(served, {})
        detail["model"].update({
            "served":           manifest.get("served_model"),
            "name":             served,
            "selection_rule":   manifest.get("selection_rule"),
            "f1_macro":         served_metrics.get("f1_macro"),
            "recall_macro":     served_metrics.get("recall_macro"),
            "weakest_class":    served_metrics.get("worst_class"),
            "weakest_recall":   served_metrics.get("min_class_recall"),
        })
    else:
        detail["model"]["manifest"] = (
            "absent - the served model is being chosen by filename order. "
            "Run: python scripts/build_manifest.py"
        )

    # Memory backs alerts, the audit trail, and the learning agent. Without it
    # detection still works but /alerts is empty and /learning/* returns 503 --
    # a state that otherwise looks identical to "a quiet network".
    #
    # Embedded Qdrant is single-writer, so the usual cause is a second process
    # (a stray server, a test run) holding qdrant_db.
    if platform.memory_provider is None:
        detail["memory"] = {
            "available": False,
            "impact": (
                "alerts, audit history and /learning/* are unavailable; "
                "detection is unaffected"
            ),
            "hint": "embedded Qdrant allows one process at a time - check for "
                    "another running server, then see the startup log",
        }
    else:
        detail["memory"] = {
            "available": True,
            "provider": type(platform.memory_provider).__name__,
        }

    # A zero-vector over the real feature schema: enough to prove the model,
    # scaler, and label encoder agree on shape and produce a usable label.
    try:
        probe = pd.DataFrame([{name: 0.0 for name in platform.artifacts.feature_cols}])
        result = predict(probe, platform.artifacts, return_proba=True)
        detail["detector"] = "ok"
        detail["probe_label"] = str(result.iloc[0]["prediction"])
    except Exception as exc:
        detail["detector"] = "failing"
        detail["reason"] = f"{type(exc).__name__}: {exc}"
        return JSONResponse(status_code=503, content={"status": "degraded", **detail})

    return {"status": "ok", **detail}
