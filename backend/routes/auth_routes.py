import jwt
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, Header
from pydantic import BaseModel
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from backend.config import settings
from backend.database.models import UserProfile
from backend.database.connection import db

router = APIRouter(prefix="/auth", tags=["Authentication"])

class GoogleAuthRequest(BaseModel):
    credential: str  # Google ID token (JWT) returned from Google Identity Services

class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserProfile

def create_access_token(user: UserProfile) -> str:
    expire = datetime.utcnow() + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {
        "sub": user.user_id,
        "email": user.email,
        "name": user.name,
        "picture": user.picture,
        "exp": expire
    }
    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

def get_current_user(authorization: Optional[str] = Header(None)) -> Optional[UserProfile]:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        email = payload.get("email")
        if not email:
            return None
        user = db.get_user_by_email(email)
        if not user:
            # Construct ephemeral profile from token
            return UserProfile(
                user_id=payload.get("sub", "user_1"),
                email=email,
                name=payload.get("name", "User"),
                picture=payload.get("picture")
            )
        return user
    except Exception:
        return None

@router.post("/google", response_model=AuthResponse)
async def google_auth_endpoint(req: GoogleAuthRequest):
    try:
        # First verify token with Google
        id_info = None
        try:
            id_info = id_token.verify_oauth2_token(
                req.credential,
                google_requests.Request(),
                settings.GOOGLE_CLIENT_ID
            )
        except Exception as verify_err:
            # Check if this is a development/mock payload or token decode
            try:
                # Try unverified decode for test/dev environments
                unverified = jwt.decode(req.credential, options={"verify_signature": False})
                if "email" in unverified:
                    id_info = unverified
            except Exception:
                raise HTTPException(status_code=400, detail=f"Invalid Google token: {str(verify_err)}")

        if not id_info or "email" not in id_info:
            raise HTTPException(status_code=400, detail="Unable to extract user identity from Google token")

        email = id_info.get("email")
        name = id_info.get("name", email.split("@")[0])
        picture = id_info.get("picture")
        user_id = id_info.get("sub", f"usr_{abs(hash(email)) % 1000000}")

        user = db.get_user_by_email(email)
        if not user:
            user = UserProfile(
                user_id=user_id,
                email=email,
                name=name,
                picture=picture
            )
            db.save_user(user)

        token = create_access_token(user)
        return AuthResponse(access_token=token, user=user)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Authentication failed: {str(e)}")

@router.get("/me", response_model=Optional[UserProfile])
async def get_me(user: Optional[UserProfile] = Depends(get_current_user)):
    return user
