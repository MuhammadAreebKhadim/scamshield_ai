from urllib.parse import urlparse, parse_qs
import tldextract
import ipaddress
from typing import Dict, Any

def parse_url_structure(url: str) -> Dict[str, Any]:
    url_cleaned = url.strip()
    if not url_cleaned.startswith(("http://", "https://")):
        # Prepend https for parsing if omitted
        raw_url = "https://" + url_cleaned
    else:
        raw_url = url_cleaned

    parsed = urlparse(raw_url)
    hostname = (parsed.hostname or "").strip()
    scheme = (parsed.scheme or "http").lower()
    is_https = scheme == "https"
    
    # Extract registered domain using tldextract
    extracted = tldextract.extract(raw_url)
    registered_domain = extracted.registered_domain
    subdomain = extracted.subdomain
    domain_name = extracted.domain
    suffix = extracted.suffix

    # Check if host is an IP
    is_ip = False
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False

    protocol_analysis = {
        "is_https": is_https,
        "protocol": scheme.upper(),
        "is_secure_transport": is_https,
        "status_label": "HTTPS (Encrypted)" if is_https else "HTTP (Unencrypted)",
        "guidance": (
            "HTTPS In-Transit Encryption Active. Important: HTTPS encrypts communication between your browser and the server, but does NOT verify the legitimacy or safety of the website owner."
            if is_https else
            "Unencrypted HTTP Connection. Sensitive data entered on this page (such as passwords or credentials) is transmitted in cleartext and subject to eavesdropping or alteration."
        )
    }

    return {
        "raw_url": raw_url,
        "protocol": scheme.upper(),
        "is_https": is_https,
        "protocol_analysis": protocol_analysis,
        "hostname": hostname,
        "domain": domain_name,
        "registered_domain": registered_domain,
        "subdomain": subdomain,
        "suffix": suffix,
        "path": parsed.path or "/",
        "query": parsed.query,
        "query_params": parse_qs(parsed.query),
        "is_ip": is_ip
    }
