from datetime import datetime

from sqlalchemy import String, Integer, DateTime
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    ip: Mapped[str] = mapped_column(String(50), unique=True)
    reason: Mapped[str] = mapped_column(String(500))
    blocked_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
