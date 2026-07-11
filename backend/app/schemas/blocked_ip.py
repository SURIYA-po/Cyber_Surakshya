from datetime import datetime
from pydantic import BaseModel, Field, IPvAnyAddress


class BlockedIPCreate(BaseModel):
    ip: IPvAnyAddress
    reason: str = Field(min_length=5, max_length=500)


class BlockedIPResponse(BaseModel):
    id: int
    ip: str
    reason: str
    blocked_at: datetime

    class Config:
        from_attributes = True
