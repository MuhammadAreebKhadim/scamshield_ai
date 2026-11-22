from fastapi import APIRouter, Depends, HTTPException
from typing import Optional
from backend.database.models import ScanRequestJob, ScanRecord, UserProfile
from backend.routes.auth_routes import get_current_user
from backend.services.job_service import scan_job_service

router = APIRouter(prefix="/scan", tags=["Job Verifier"])

@router.post("/job", response_model=ScanRecord)
async def scan_job_endpoint(req: ScanRequestJob, user: Optional[UserProfile] = Depends(get_current_user)):
    if not req.company_name.strip() and not req.job_description.strip():
        raise HTTPException(status_code=400, detail="Company name or job description is required")

    user_id = user.user_id if user else "anonymous"
    user_email = user.email if user else "anonymous@scamshield.ai"

    result = await scan_job_service(
        company_name=req.company_name,
        job_title=req.job_title,
        recruiter_email=req.recruiter_email or "",
        job_description=req.job_description,
        salary_or_terms=req.salary_or_terms or "",
        application_url=req.application_url or "",
        user_id=user_id,
        user_email=user_email
    )
    return result
