from datetime import datetime
from pydantic import BaseModel, Field, IPvAnyAddress

from app.enums.alert import SeverityEnum, AlertStatusEnum


class AlertCreate(BaseModel):
    attack_type: str = Field(min_length=3, max_length=100)
    severity: SeverityEnum
    source_ip: IPvAnyAddress
    status: AlertStatusEnum = AlertStatusEnum.NEW


class AlertResponse(BaseModel):
    id: int
    attack_type: str
    severity: str
    source_ip: str
    status: str
    created_at: datetime

    class Config:
        from_attributes = True
