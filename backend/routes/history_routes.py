from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
from backend.database.models import ScanRecord
from backend.database.connection import db

router = APIRouter(prefix="/scan", tags=["Scan History"])

@router.get("/history", response_model=List[ScanRecord])
async def get_scan_history(
    limit: int = Query(50, ge=1, le=200),
    user_id: Optional[str] = Query(None),
    input_type: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None)
):
    scans = db.get_recent_scans(limit=limit, user_id=user_id)
    if input_type:
        scans = [s for s in scans if s.input_type.lower() == input_type.lower()]
    if risk_level:
        scans = [s for s in scans if s.risk_level.upper() == risk_level.upper()]
    return scans

@router.get("/{scan_id}", response_model=ScanRecord)
async def get_single_scan(scan_id: str):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan with ID '{scan_id}' not found")
    return scan
