from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.blocked_ip import BlockedIP


class BlockedRepository:

    @staticmethod
    async def create(db: AsyncSession, blocked_ip: BlockedIP):
        db.add(blocked_ip)
        await db.commit()
        await db.refresh(blocked_ip)
        return blocked_ip

    @staticmethod
    async def get_all(db: AsyncSession):
        result = await db.execute(
            select(BlockedIP).order_by(BlockedIP.blocked_at.desc())
        )
        return result.scalars().all()

    @staticmethod
    async def get_by_id(db: AsyncSession, blocked_id: int):
        result = await db.execute(
            select(BlockedIP).where(BlockedIP.id == blocked_id)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def get_by_ip(db: AsyncSession, ip: str):
        result = await db.execute(
            select(BlockedIP).where(BlockedIP.ip == ip)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def count(db: AsyncSession) -> int:
        result = await db.execute(select(func.count(BlockedIP.id)))
        return result.scalar_one()

    @staticmethod
    async def delete(db: AsyncSession, blocked_ip: BlockedIP):
        await db.delete(blocked_ip)
        await db.commit()
