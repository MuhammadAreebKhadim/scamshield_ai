import requests
from datetime import datetime
from typing import Dict, Any

def check_domain_age(domain: str) -> Dict[str, Any]:
    if not domain or domain.replace(".", "").isdigit():
        return {
            "status": "skipped",
            "age_days": None,
            "registration_date": None,
            "is_new": False,
            "message": "Unavailable — Registration data not retrieved.",
            "detail": "Target is a direct numeric IP address without RDAP domain registration."
        }

    rdap_url = f"https://rdap.org/domain/{domain}"
    try:
        resp = requests.get(rdap_url, timeout=5, allow_redirects=True)
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
                age_days = (datetime.utcnow() - reg_dt).days

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

    return {
        "status": "unavailable",
        "age_days": None,
        "registration_date": None,
        "is_new": False,
        "message": "Unavailable — Registration data not retrieved.",
        "detail": "RDAP registry did not respond or registration records were not returned for this domain."
    }
