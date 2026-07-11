from datetime import datetime
from pydantic import BaseModel, Field

from app.enums.agent import AgentStatusEnum


class AgentCreate(BaseModel):
    agent_name: str = Field(min_length=3, max_length=100)
    status: AgentStatusEnum = AgentStatusEnum.ONLINE


class AgentResponse(BaseModel):
    id: int
    agent_name: str
    status: str
    heartbeat: datetime

    class Config:
        from_attributes = True
