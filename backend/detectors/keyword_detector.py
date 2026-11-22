from typing import List, Dict, Any

# Standard benign authentication terms frequently present on legitimate platforms
AUTH_PATH_KEYWORDS = ["login", "signin", "auth", "authenticate", "session", "user"]

# High-risk financial, social engineering, and credential harvesting keywords
DECEPTIVE_SUSPICIOUS_KEYWORDS = [
    "verify", "secure", "account", "password", "update", "banking",
    "reward", "claim", "free", "payment", "wallet", "confirm",
    "security", "suspended", "urgent", "bonus", "airdrop", "kyc",
    "recover", "validation", "support", "billing", "unusual", "locked"
]

def detect_suspicious_keywords(url_data: Dict[str, Any]) -> Dict[str, Any]:
    hostname = (url_data.get("hostname") or "").lower()
    path = (url_data.get("path") or "").lower()
    query = (url_data.get("query") or "").lower()

    # Detect high-risk deceptive terms
    deceptive_in_host = [kw for kw in DECEPTIVE_SUSPICIOUS_KEYWORDS if kw in hostname]
    deceptive_in_path = [kw for kw in DECEPTIVE_SUSPICIOUS_KEYWORDS if kw in path]
    deceptive_in_query = [kw for kw in DECEPTIVE_SUSPICIOUS_KEYWORDS if kw in query]
    deceptive_matches = list(set(deceptive_in_host + deceptive_in_path + deceptive_in_query))

    # Detect benign standard authentication terms
    auth_in_host = [kw for kw in AUTH_PATH_KEYWORDS if kw in hostname]
    auth_in_path = [kw for kw in AUTH_PATH_KEYWORDS if kw in path]
    auth_in_query = [kw for kw in AUTH_PATH_KEYWORDS if kw in query]
    auth_matches = list(set(auth_in_host + auth_in_path + auth_in_query))

    all_matches = list(set(deceptive_matches + auth_matches))

    # If only benign auth terms like 'login' appear in the path, it is a normal URL keyword
    only_auth_keyword = len(deceptive_matches) == 0 and len(auth_matches) > 0 and len(auth_in_host) == 0

    return {
        "detected_keywords": all_matches,
        "deceptive_keywords": deceptive_matches,
        "auth_keywords": auth_matches,
        "only_auth_keyword": only_auth_keyword,
        "count": len(all_matches),
        "in_hostname": list(set(deceptive_in_host + auth_in_host)),
        "in_path": list(set(deceptive_in_path + auth_in_path)),
        "in_query": list(set(deceptive_in_query + auth_in_query)),
        "has_suspicious_keywords": len(deceptive_matches) > 0 or len(auth_in_host) > 0,
        "note": "Standard authentication path (login/signin alone carries minimal risk)" if only_auth_keyword else None
    }
