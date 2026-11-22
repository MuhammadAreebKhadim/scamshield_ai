from fastapi import APIRouter
from backend.database.models import DashboardStats
from backend.database.connection import db

router = APIRouter(prefix="/dashboard", tags=["Dashboard Statistics"])

@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_statistics():
    return db.get_dashboard_stats()
