import ipaddress
from typing import Dict, Any

def detect_ip_based_url(url_data: Dict[str, Any]) -> Dict[str, Any]:
    hostname = (url_data.get("hostname") or "").strip()
    is_ip = False
    ip_type = None
    is_private = False
    is_loopback = False
    ip_classification = "Domain Host"
    description = "Domain name host"

    try:
        ip_obj = ipaddress.ip_address(hostname)
        is_ip = True
        ip_type = f"IPv{ip_obj.version}"
        is_private = ip_obj.is_private
        is_loopback = ip_obj.is_loopback

        if is_loopback:
            ip_classification = "Loopback IP (Localhost / 127.0.0.1)"
            description = f"{hostname} is a loopback address pointing to the local machine. It cannot be accessed over external networks."
        elif is_private:
            ip_classification = "Private IP (Local Area Network / RFC 1918)"
            description = f"{hostname} is a private unroutable IP (RFC 1918). It is only accessible within local private networks and cannot be reached from the public Internet. Often points to local router portals or intranet assets."
        elif ip_obj.is_reserved:
            ip_classification = "Reserved IP Address"
            description = f"{hostname} is an IETF reserved address range."
        elif ip_obj.is_link_local:
            ip_classification = "Link-Local IP (APIPA)"
            description = f"{hostname} is a non-routable link-local address."
        else:
            ip_classification = "Public IP (Direct Host)"
            description = f"{hostname} is a public IP address hosting services directly without DNS domain attribution."

    except ValueError:
        is_ip = False

    return {
        "is_ip": is_ip,
        "ip_type": ip_type,
        "is_private": is_private,
        "is_loopback": is_loopback,
        "ip_classification": ip_classification,
        "description": description,
        "warning": (
            f"URL points to a {ip_classification.lower()} ({hostname}) rather than a legitimate domain name"
            if is_ip else None
        )
    }
