from sqlalchemy import String, Integer, Float, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"))
    prediction: Mapped[str] = mapped_column(String(100))
    confidence: Mapped[float] = mapped_column(Float)
    summary: Mapped[str] = mapped_column(String(500))
