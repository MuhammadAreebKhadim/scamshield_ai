import requests
from typing import Dict, Any
from backend.config import settings

URLHAUS_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"

def check_urlhaus(url: str) -> Dict[str, Any]:
    if not settings.URLHAUS_API_KEY:
        return {"status": "unavailable", "reason": "API key not configured", "is_malicious": False}

    headers = {
        "Auth-Key": settings.URLHAUS_API_KEY
    }
    payload = {"url": url}

    try:
        resp = requests.post(URLHAUS_ENDPOINT, headers=headers, data=payload, timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            query_status = data.get("query_status")

            if query_status == "ok":
                return {
                    "status": "threat_found",
                    "is_malicious": True,
                    "url_status": data.get("url_status", "unknown"),
                    "threat": data.get("threat", "malware_download"),
                    "tags": data.get("tags") or [],
                    "date_added": data.get("date_added"),
                    "host": data.get("host"),
                    "reporter": data.get("reporter")
                }
            elif query_status == "no_results":
                return {
                    "status": "no_match",
                    "is_malicious": False,
                    "message": "No known malware match in URLhaus database."
                }
            else:
                return {
                    "status": "unknown_query_status",
                    "is_malicious": False,
                    "message": query_status
                }
        else:
            return {
                "status": "unavailable",
                "is_malicious": False,
                "message": f"URLhaus API returned HTTP {resp.status_code}"
            }
    except Exception as e:
        return {
            "status": "unavailable",
            "is_malicious": False,
            "message": f"URLhaus request failed: {str(e)}"
        }
