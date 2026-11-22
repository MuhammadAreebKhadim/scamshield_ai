from fastapi import APIRouter, Depends, HTTPException
from typing import Optional
from backend.database.models import ScanRequestMessage, ScanRecord, UserProfile
from backend.routes.auth_routes import get_current_user
from backend.services.message_service import scan_message_service

router = APIRouter(prefix="/scan", tags=["Message Scanner"])

@router.post("/message", response_model=ScanRecord)
async def scan_message_endpoint(req: ScanRequestMessage, user: Optional[UserProfile] = Depends(get_current_user)):
    content = req.content.strip()
    if not content:
        raise HTTPException(status_code=400, detail="Message content cannot be empty")

    user_id = user.user_id if user else "anonymous"
    user_email = user.email if user else "anonymous@scamshield.ai"

    result = await scan_message_service(
        content=content,
        channel=req.channel or "Email",
        user_id=user_id,
        user_email=user_email
    )
    return result
