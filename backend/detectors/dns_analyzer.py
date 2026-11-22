import socket
import ipaddress
from typing import Dict, Any, List

def analyze_dns_records(url_data: Dict[str, Any]) -> Dict[str, Any]:
    hostname = (url_data.get("hostname") or "").strip()

    # 1. If hostname is already an IP
    try:
        ip_obj = ipaddress.ip_address(hostname)
        return {
            "is_direct_ip": True,
            "resolved": True,
            "resolved_ips": [hostname],
            "ip_count": 1,
            "dns_status": "Direct IP (Bypasses DNS)",
            "message": f"Host is direct numeric {ip_obj.version} address ({hostname}). Does not rely on DNS resolution.",
            "cname": None
        }
    except ValueError:
        pass

    if not hostname:
        return {
            "is_direct_ip": False,
            "resolved": False,
            "resolved_ips": [],
            "ip_count": 0,
            "dns_status": "Invalid Host",
            "message": "Empty or invalid hostname.",
            "cname": None
        }

    # 2. Query DNS records via socket.getaddrinfo
    try:
        addr_infos = socket.getaddrinfo(hostname, 80, socket.AF_UNSPEC, socket.SOCK_STREAM)
        unique_ips: List[str] = list(set([item[4][0] for item in addr_infos]))
        
        # Check canonical host / alias
        canonical_name = None
        try:
            canonical_name, _, _ = socket.gethostbyname_ex(hostname)
        except Exception:
            pass

        return {
            "is_direct_ip": False,
            "resolved": True,
            "resolved_ips": unique_ips,
            "ip_count": len(unique_ips),
            "dns_status": f"Resolved ({len(unique_ips)} IPs)",
            "message": f"Domain resolved successfully to {len(unique_ips)} IP address(es): {', '.join(unique_ips[:3])}",
            "cname": canonical_name if canonical_name and canonical_name != hostname else None
        }
    except socket.gaierror as e:
        return {
            "is_direct_ip": False,
            "resolved": False,
            "resolved_ips": [],
            "ip_count": 0,
            "dns_status": "NXDOMAIN / Unresolved",
            "message": f"Domain failed DNS resolution. Host does not currently map to active infrastructure (NXDOMAIN).",
            "cname": None
        }
    except Exception as e:
        return {
            "is_direct_ip": False,
            "resolved": False,
            "resolved_ips": [],
            "ip_count": 0,
            "dns_status": "DNS Lookup Failed",
            "message": f"DNS query failed or timed out ({str(e)}).",
            "cname": None
        }
