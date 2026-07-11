from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.blocked_ip import BlockedIP
from app.schemas.blocked_ip import BlockedIPCreate, BlockedIPResponse
from app.repositories.blocked_repository import BlockedRepository
from app.services.cache_service import invalidate_stats_cache

router = APIRouter(prefix="/blocked-ips", tags=["Blocked IPs"])


@router.post("", response_model=BlockedIPResponse, status_code=status.HTTP_201_CREATED)
async def create_blocked_ip(payload: BlockedIPCreate, db: AsyncSession = Depends(get_db)):
    existing = await BlockedRepository.get_by_ip(db, str(payload.ip))
    if existing:
        raise HTTPException(status_code=400, detail="IP already blocked")

    blocked_ip = BlockedIP(ip=str(payload.ip), reason=payload.reason)
    created = await BlockedRepository.create(db, blocked_ip)
    await invalidate_stats_cache()
    return created


@router.get("", response_model=list[BlockedIPResponse])
async def get_blocked_ips(db: AsyncSession = Depends(get_db)):
    return await BlockedRepository.get_all(db)


@router.get("/{blocked_id}", response_model=BlockedIPResponse)
async def get_blocked_ip(blocked_id: int, db: AsyncSession = Depends(get_db)):
    blocked_ip = await BlockedRepository.get_by_id(db, blocked_id)
    if not blocked_ip:
        raise HTTPException(status_code=404, detail="Blocked IP not found")
    return blocked_ip


@router.delete("/{blocked_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_blocked_ip(blocked_id: int, db: AsyncSession = Depends(get_db)):
    blocked_ip = await BlockedRepository.get_by_id(db, blocked_id)
    if not blocked_ip:
        raise HTTPException(status_code=404, detail="Blocked IP not found")
    await BlockedRepository.delete(db, blocked_ip)
