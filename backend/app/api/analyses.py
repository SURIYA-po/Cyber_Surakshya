from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.analysis import Analysis
from app.schemas.analysis import AnalysisCreate, AnalysisResponse
from app.repositories.analysis_repository import AnalysisRepository
from app.repositories.alert_repository import AlertRepository
from app.services.cache_service import invalidate_stats_cache

router = APIRouter(prefix="/analyses", tags=["Analyses"])


@router.post("", response_model=AnalysisResponse, status_code=status.HTTP_201_CREATED)
async def create_analysis(payload: AnalysisCreate, db: AsyncSession = Depends(get_db)):
    alert = await AlertRepository.get_by_id(db, payload.alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    analysis = Analysis(
        alert_id=payload.alert_id,
        prediction=payload.prediction,
        confidence=payload.confidence,
        summary=payload.summary
    )
    created = await AnalysisRepository.create(db, analysis)
    await invalidate_stats_cache()
    return created


@router.get("", response_model=list[AnalysisResponse])
async def get_analyses(db: AsyncSession = Depends(get_db)):
    return await AnalysisRepository.get_all(db)


@router.get("/{analysis_id}", response_model=AnalysisResponse)
async def get_analysis(analysis_id: int, db: AsyncSession = Depends(get_db)):
    analysis = await AnalysisRepository.get_by_id(db, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return analysis


@router.delete("/{analysis_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_analysis(analysis_id: int, db: AsyncSession = Depends(get_db)):
    analysis = await AnalysisRepository.get_by_id(db, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    await AnalysisRepository.delete(db, analysis)
