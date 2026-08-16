"""Alerts and analyses, projected from stored detection records.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from api.projections import (
    find_detection_record,
    load_alert,
    load_alert_detail,
    load_frontend_state_from_memory,
)
from api.runtime import ensure_runtime, platform

router = APIRouter(tags=["alerts"])


@router.get("/alerts")
def get_alerts():
    alerts, _, _ = load_frontend_state_from_memory()
    return JSONResponse(content=sorted(alerts, key=lambda x: x["created_at"], reverse=True))

@router.get("/alerts/{alert_id}")
def get_alert_by_id(alert_id: str):
    # Resolves this alert's own chain rather than projecting the whole page and
    # searching it for one id.
    alert = load_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return JSONResponse(content=alert)

@router.get("/alerts/{alert_id}/detail")
def get_alert_detail(alert_id: str):
    payload = load_alert_detail(alert_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return JSONResponse(content=payload)

@router.delete("/alerts/{alert_id}")
def delete_alert(alert_id: str):
    """Delete the detection record an alert is projected from.

    This used to filter the MOCK_ALERTS list, so once real detections existed
    the endpoint returned {"status": "deleted"} and changed nothing — the alert
    reappeared on the next refresh.

    Alerts are a projection over stored detections, so deleting the alert means
    deleting that record. The linked analysis and decision records are left in
    place deliberately: they are the audit trail, and an analyst dismissing an
    alert must not erase evidence of what the platform decided.
    """
    ensure_runtime()
    if platform.memory_provider is None:
        raise HTTPException(
            status_code=503,
            detail="Memory provider unavailable; alerts cannot be modified.",
        )

    # Addressed directly rather than by projecting every alert and searching.
    detection = find_detection_record(alert_id)
    if detection is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    record_id = detection.record_id or alert_id
    try:
        deleted = platform.memory_provider.delete("detections", str(record_id))
    except Exception as exc:
        raise HTTPException(
            status_code=500, detail=f"Could not delete alert: {exc}"
        ) from exc

    if not deleted:
        raise HTTPException(status_code=404, detail="Alert record not found in memory")
    return JSONResponse(content={"status": "deleted", "id": alert_id})
