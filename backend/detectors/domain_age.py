import os
import requests
from datetime import datetime, timezone
from typing import Dict, Any

def extract_apex_domain(hostname: str) -> str:
    parts = hostname.lower().strip().split(".")
    if len(parts) <= 2:
        return hostname.lower().strip()
    
    two_part_suffixes = {
        "co.uk", "org.uk", "gov.uk", "ac.uk",
        "com.au", "net.au", "org.au", "edu.au",
        "co.nz", "net.nz", "org.nz",
        "co.jp", "ne.jp", "or.jp",
        "com.br", "net.br", "org.br",
        "com.pk", "org.pk", "edu.pk", "net.pk",
        "co.in", "net.in", "org.in",
        "com.sg", "org.sg", "com.my", "com.tr"
    }
    last_two = ".".join(parts[-2:])
    if last_two in two_part_suffixes and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

def check_domain_age(raw_domain: str) -> Dict[str, Any]:
    if not raw_domain or raw_domain.replace(".", "").isdigit():
        return {
            "status": "skipped",
            "age_days": None,
            "registration_date": None,
            "is_new": False,
            "message": "Unavailable — Registration data not retrieved.",
            "detail": "Target is a direct numeric IP address without RDAP domain registration."
        }

    domain = extract_apex_domain(raw_domain)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json"
    }

    # 1. Primary: RDAP registry lookups
    rdap_url = f"https://rdap.org/domain/{domain}"
    try:
        resp = requests.get(rdap_url, headers=headers, timeout=5, allow_redirects=True)
        if resp.status_code == 200:
            data = resp.json()
            events = data.get("events", [])
            reg_date_str = None
            for ev in events:
                if ev.get("eventAction") in ["registration", "created"]:
                    reg_date_str = ev.get("eventDate")
                    break

            if reg_date_str:
                cleaned_date = reg_date_str.replace("Z", "+00:00")
                if "+" in cleaned_date:
                    cleaned_date = cleaned_date.split("+")[0]
                reg_dt = datetime.fromisoformat(cleaned_date)
                now = datetime.now(timezone.utc).replace(tzinfo=None)
                age_days = max(0, (now - reg_dt).days)

                is_new = age_days < 30
                is_suspiciously_young = age_days < 90

                return {
                    "status": "success",
                    "age_days": age_days,
                    "registration_date": reg_dt.strftime("%Y-%m-%d"),
                    "is_new": is_new,
                    "is_suspiciously_young": is_suspiciously_young,
                    "message": f"Registered {age_days} days ago ({reg_dt.strftime('%Y-%m-%d')})",
                    "detail": "Domain age retrieved via RDAP authority."
                }
    except Exception:
        pass

    # 2. Fallback: VirusTotal domain creation date
    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    if vt_key:
        try:
            vt_resp = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": vt_key},
                timeout=5
            )
            if vt_resp.status_code == 200:
                vt_data = vt_resp.json()
                c_date = vt_data.get("data", {}).get("attributes", {}).get("creation_date")
                if c_date:
                    reg_dt = datetime.fromtimestamp(c_date, tz=timezone.utc).replace(tzinfo=None)
                    now = datetime.now(timezone.utc).replace(tzinfo=None)
                    age_days = max(0, (now - reg_dt).days)
                    is_new = age_days < 30
                    is_suspiciously_young = age_days < 90

                    return {
                        "status": "success",
                        "age_days": age_days,
                        "registration_date": reg_dt.strftime("%Y-%m-%d"),
                        "is_new": is_new,
                        "is_suspiciously_young": is_suspiciously_young,
                        "message": f"Registered {age_days} days ago ({reg_dt.strftime('%Y-%m-%d')})",
                        "detail": "Domain age retrieved via VirusTotal registry telemetry."
                    }
        except Exception:
            pass

    return {
        "status": "unavailable",
        "age_days": None,
        "registration_date": None,
        "is_new": False,
        "message": "Unavailable — Registration data not retrieved.",
        "detail": "RDAP registry did not respond or registration records were not returned for this domain."
    }
