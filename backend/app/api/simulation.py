from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.services.coordinator import Coordinator
from app.services.workflow_engine import WorkflowEngine

router = APIRouter(prefix="/simulation", tags=["Simulation"])


@router.post("/simulate-attack")
async def simulate_attack(db: AsyncSession = Depends(get_db)):
    """
    Execute the complete SOC incident workflow.

    Steps:
    1. Generate random attack
    2. Calculate threat score
    3. Save alert to database
    4. Generate AI analysis
    5. Save analysis to database
    6. Determine response action
    7. Block IP if required
    8. Update agent heartbeats
    """
    return await WorkflowEngine.execute(
        lambda: Coordinator.execute(db)
    )
