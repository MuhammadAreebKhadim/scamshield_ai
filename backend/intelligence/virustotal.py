import base64
import requests
import time
from typing import Dict, Any
from backend.config import settings

VT_BASE_URL = "https://www.virustotal.com/api/v3"

def encode_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def check_virustotal(url: str) -> Dict[str, Any]:
    if not settings.VIRUSTOTAL_API_KEY:
        return {"status": "unavailable", "reason": "API key not configured", "is_malicious": False}

    headers = {
        "x-apikey": settings.VIRUSTOTAL_API_KEY
    }

    url_id = encode_url_id(url)

    try:
        # Try fetching existing report
        report_resp = requests.get(f"{VT_BASE_URL}/urls/{url_id}", headers=headers, timeout=8)
        if report_resp.status_code == 200:
            data = report_resp.json()
            attributes = data.get("data", {}).get("attributes", {})
            last_analysis_stats = attributes.get("last_analysis_stats", {})

            malicious = last_analysis_stats.get("malicious", 0)
            suspicious = last_analysis_stats.get("suspicious", 0)
            harmless = last_analysis_stats.get("harmless", 0)
            undetected = last_analysis_stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected

            return {
                "status": "success",
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total_vendors": total,
                "is_malicious": malicious > 0,
                "is_suspicious": suspicious > 0,
                "summary": f"{malicious} security vendors flagged this URL on VirusTotal ({total} total engines)"
            }
        elif report_resp.status_code == 404:
            # Submit for scan
            scan_resp = requests.post(f"{VT_BASE_URL}/urls", headers=headers, data={"url": url}, timeout=8)
            if scan_resp.status_code in [200, 201]:
                analysis_id = scan_resp.json().get("data", {}).get("id")
                if analysis_id:
                    time.sleep(1.5)
                    a_resp = requests.get(f"{VT_BASE_URL}/analyses/{analysis_id}", headers=headers, timeout=8)
                    if a_resp.status_code == 200:
                        a_stats = a_resp.json().get("data", {}).get("attributes", {}).get("stats", {})
                        mal = a_stats.get("malicious", 0)
                        susp = a_stats.get("suspicious", 0)
                        harm = a_stats.get("harmless", 0)
                        undet = a_stats.get("undetected", 0)
                        tot = mal + susp + harm + undet
                        return {
                            "status": "success",
                            "malicious": mal,
                            "suspicious": susp,
                            "harmless": harm,
                            "undetected": undet,
                            "total_vendors": tot,
                            "is_malicious": mal > 0,
                            "is_suspicious": susp > 0,
                            "summary": f"{mal} security vendors flagged this URL on VirusTotal ({tot} total engines)"
                        }

            return {
                "status": "pending_analysis",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "total_vendors": 0,
                "is_malicious": False,
                "summary": "URL submitted to VirusTotal queue."
            }
        elif report_resp.status_code == 429:
            return {
                "status": "rate_limited",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "total_vendors": 0,
                "is_malicious": False,
                "summary": "VirusTotal public quota limit reached."
            }
        else:
            return {
                "status": "unavailable",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "total_vendors": 0,
                "is_malicious": False,
                "summary": f"VirusTotal returned HTTP {report_resp.status_code}"
            }
    except Exception as e:
        return {
            "status": "unavailable",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "total_vendors": 0,
            "is_malicious": False,
            "summary": f"VirusTotal query failed: {str(e)}"
        }
