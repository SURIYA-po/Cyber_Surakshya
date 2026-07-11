from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent import Agent


class AgentRepository:

    @staticmethod
    async def create(db: AsyncSession, agent: Agent):
        db.add(agent)
        await db.commit()
        await db.refresh(agent)
        return agent

    @staticmethod
    async def get_all(db: AsyncSession):
        result = await db.execute(select(Agent))
        return result.scalars().all()

    @staticmethod
    async def get_by_id(db: AsyncSession, agent_id: int):
        result = await db.execute(
            select(Agent).where(Agent.id == agent_id)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def get_by_name(db: AsyncSession, name: str):
        result = await db.execute(
            select(Agent).where(Agent.agent_name == name)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def delete(db: AsyncSession, agent: Agent):
        await db.delete(agent)
        await db.commit()
