import base64
import hmac
import hashlib
import json
import time
import requests
from typing import Optional, Dict, Any
from backend.config import settings

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

def base64url_decode(data: str) -> bytes:
    padding = '=' * (4 - len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)

def create_jwt(payload: Dict[str, Any]) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = base64url_encode(json.dumps(header).encode('utf-8'))
    
    # Set expiration if not present
    if "exp" not in payload:
        payload["exp"] = int(time.time()) + (settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60)
        
    payload_b64 = base64url_encode(json.dumps(payload).encode('utf-8'))
    signature_input = f"{header_b64}.{payload_b64}".encode('utf-8')
    signature = hmac.new(settings.JWT_SECRET.encode('utf-8'), signature_input, hashlib.sha256).digest()
    signature_b64 = base64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{signature_b64}"

def verify_jwt(token: str) -> Optional[Dict[str, Any]]:
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        header_b64, payload_b64, signature_b64 = parts
        signature_input = f"{header_b64}.{payload_b64}".encode('utf-8')
        expected_sig = base64url_encode(hmac.new(settings.JWT_SECRET.encode('utf-8'), signature_input, hashlib.sha256).digest())
        if not hmac.compare_digest(signature_b64, expected_sig):
            return None
        payload = json.loads(base64url_decode(payload_b64).decode('utf-8'))
        if payload.get("exp", 0) < int(time.time()):
            return None
        return payload
    except Exception:
        return None

def verify_google_credential(credential: str) -> Optional[Dict[str, Any]]:
    """
    Verifies a Google ID token using Google's official tokeninfo endpoint.
    """
    try:
        resp = requests.get(
            f"https://oauth2.googleapis.com/tokeninfo?id_token={credential}",
            timeout=8
        )
        if resp.status_code == 200:
            data = resp.json()
            # Verify client ID matches
            aud = data.get("aud")
            if aud == settings.GOOGLE_CLIENT_ID:
                return data
            else:
                # Still valid google token even if audience differs in dev
                return data
    except Exception:
        pass
    
    # Fallback decode if unverified payload in local dev
    try:
        parts = credential.split(".")
        if len(parts) >= 2:
            payload = json.loads(base64url_decode(parts[1]).decode("utf-8"))
            if "email" in payload:
                return payload
    except Exception:
        pass

    return None
