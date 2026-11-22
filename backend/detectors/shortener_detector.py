from typing import Dict, Any

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", 
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "rb.gy", "shorturl.at", 
    "tiny.cc", "lnkd.in", "rebrand.ly", "qr.ae", "v.gd", "trib.al",
    "clck.ru", "s.id", "soo.gd", "tny.im", "bl.ink", "hyperurl.co"
}

def detect_url_shortener(url_data: Dict[str, Any]) -> Dict[str, Any]:
    hostname = (url_data.get("hostname") or "").lower()
    registered_domain = (url_data.get("registered_domain") or "").lower()

    is_shortener = (
        hostname in KNOWN_SHORTENERS or 
        registered_domain in KNOWN_SHORTENERS or
        any(hostname.endswith("." + s) for s in KNOWN_SHORTENERS)
    )

    matched_service = next(
        (s for s in KNOWN_SHORTENERS if hostname == s or registered_domain == s or hostname.endswith("." + s)),
        None
    )

    return {
        "is_shortened": is_shortener,
        "service": matched_service,
        "warning": (
            f"URL Shortener Detected ({matched_service}). Link conceals destination URL; frequently used in phishing and smishing lures."
            if is_shortener else None
        )
    }
