from pydantic import BaseModel, Field


class AnalysisCreate(BaseModel):
    alert_id: int
    prediction: str = Field(min_length=2, max_length=100)
    confidence: float = Field(ge=0, le=100)
    summary: str = Field(min_length=5, max_length=500)


class AnalysisResponse(BaseModel):
    id: int
    alert_id: int
    prediction: str
    confidence: float
    summary: str

    class Config:
        from_attributes = True
