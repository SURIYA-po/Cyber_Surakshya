from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.alert import Alert
from app.schemas.alert import AlertCreate, AlertResponse
from app.repositories.alert_repository import AlertRepository
from app.repositories.analysis_repository import AnalysisRepository
from app.services.cache_service import invalidate_stats_cache

router = APIRouter(
    prefix="/alerts",
    tags=["Alerts"]
)


@router.post("", response_model=AlertResponse, status_code=status.HTTP_201_CREATED)
async def create_alert(payload: AlertCreate, db: AsyncSession = Depends(get_db)):
    alert = Alert(
        attack_type=payload.attack_type,
        severity=payload.severity.value,
        source_ip=str(payload.source_ip),
        status=payload.status.value
    )
    created = await AlertRepository.create(db, alert)
    await invalidate_stats_cache()
    return created


@router.get("", response_model=list[AlertResponse])
async def get_alerts(db: AsyncSession = Depends(get_db)):
    return await AlertRepository.get_all(db)


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(alert_id: int, db: AsyncSession = Depends(get_db)):
    alert = await AlertRepository.get_by_id(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.get("/{alert_id}/detail")
async def get_alert_detail(alert_id: int, db: AsyncSession = Depends(get_db)):
    """
    Returns full incident detail: alert + analysis + response action.
    Used by the Alert Detail page on the frontend.
    """
    alert = await AlertRepository.get_by_id(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    analysis = await AnalysisRepository.get_by_alert_id(db, alert_id)

    return {
        "alert": {
            "id": alert.id,
            "attack_type": alert.attack_type,
            "severity": alert.severity,
            "source_ip": alert.source_ip,
            "status": alert.status,
            "created_at": alert.created_at.isoformat()
        },
        "analysis": {
            "id": analysis.id,
            "prediction": analysis.prediction,
            "confidence": analysis.confidence,
            "summary": analysis.summary
        } if analysis else None,
        "response_action": _derive_response(alert.severity)
    }


def _derive_response(severity: str) -> str:
    mapping = {
        "CRITICAL": "Block IP",
        "HIGH": "Block IP",
        "MEDIUM": "Investigate",
        "LOW": "Monitor"
    }
    return mapping.get(severity, "Monitor")


@router.delete("/{alert_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_alert(alert_id: int, db: AsyncSession = Depends(get_db)):
    alert = await AlertRepository.get_by_id(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    await AlertRepository.delete(db, alert)
    await invalidate_stats_cache()
