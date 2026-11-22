import requests
from typing import Dict, Any
from backend.config import settings

GSB_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

def check_google_safe_browsing(url: str) -> Dict[str, Any]:
    if not settings.GOOGLE_SAFE_BROWSING_API_KEY:
        return {
            "status": "unavailable",
            "is_threat_found": False,
            "matches": [],
            "summary": "Google Safe Browsing key not configured"
        }

    url_target = f"{GSB_ENDPOINT}?key={settings.GOOGLE_SAFE_BROWSING_API_KEY}"
    payload = {
        "client": {
            "clientId": "scamshield",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        resp = requests.post(url_target, json=payload, timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            matches = data.get("matches", [])
            threat_found = len(matches) > 0
            threat_types = [m.get("threatType") for m in matches if m.get("threatType")]

            return {
                "status": "threat_found" if threat_found else "no_match",
                "is_threat_found": threat_found,
                "matches": matches,
                "threat_types": threat_types,
                "summary": f"Known unsafe threat detected: {', '.join(threat_types)}" if threat_found else "No matches in Google Safe Browsing database."
            }
        else:
            return {
                "status": "unavailable",
                "is_threat_found": False,
                "matches": [],
                "summary": f"Google Safe Browsing returned HTTP {resp.status_code}"
            }
    except Exception as e:
        return {
            "status": "unavailable",
            "is_threat_found": False,
            "matches": [],
            "summary": f"Google Safe Browsing check failed: {str(e)}"
        }
