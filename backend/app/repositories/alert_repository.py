from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert


class AlertRepository:

    @staticmethod
    async def create(db: AsyncSession, alert: Alert):
        db.add(alert)
        await db.commit()
        await db.refresh(alert)
        return alert

    @staticmethod
    async def get_all(db: AsyncSession):
        result = await db.execute(select(Alert).order_by(Alert.created_at.desc()))
        return result.scalars().all()

    @staticmethod
    async def get_by_id(db: AsyncSession, alert_id: int):
        result = await db.execute(
            select(Alert).where(Alert.id == alert_id)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def count(db: AsyncSession) -> int:
        result = await db.execute(select(func.count(Alert.id)))
        return result.scalar_one()

    @staticmethod
    async def delete(db: AsyncSession, alert: Alert):
        await db.delete(alert)
        await db.commit()
