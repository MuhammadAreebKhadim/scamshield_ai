from fastapi import APIRouter, Depends, HTTPException
from typing import Optional
from backend.database.models import ScanRequestURL, ScanRecord, UserProfile
from backend.routes.auth_routes import get_current_user
from backend.services.url_service import scan_url_service

router = APIRouter(prefix="/scan", tags=["URL Scanner"])

@router.post("/url", response_model=ScanRecord)
async def scan_url_endpoint(req: ScanRequestURL, user: Optional[UserProfile] = Depends(get_current_user)):
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    user_id = user.user_id if user else "anonymous"
    user_email = user.email if user else "anonymous@scamshield.ai"

    result = await scan_url_service(url, user_id=user_id, user_email=user_email)
    return result
