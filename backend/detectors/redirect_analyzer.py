import ipaddress
import requests
from urllib.parse import urlparse
from typing import Dict, Any, List

def analyze_redirect_chain(raw_url: str, url_data: Dict[str, Any]) -> Dict[str, Any]:
    hostname = (url_data.get("hostname") or "").strip()

    # Safety check: Prevent SSRF against local / private infrastructure
    try:
        ip_obj = ipaddress.ip_address(hostname)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
            return {
                "has_redirects": False,
                "redirect_count": 0,
                "final_url": raw_url,
                "chain": [],
                "cross_domain": False,
                "status": "skipped",
                "note": "Private network IP target — redirect tracing bypassed for security."
            }
    except ValueError:
        pass

    if hostname in ["localhost", "127.0.0.1", "0.0.0.0", "::1"]:
        return {
            "has_redirects": False,
            "redirect_count": 0,
            "final_url": raw_url,
            "chain": [],
            "cross_domain": False,
            "status": "skipped",
            "note": "Localhost target — redirect tracing bypassed."
        }

    chain: List[Dict[str, Any]] = []
    has_redirects = False
    final_url = raw_url
    cross_domain = False

    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        }
        # Safe stream request with fast timeout to capture response history without downloading payloads
        resp = requests.get(raw_url, headers=headers, timeout=3.5, allow_redirects=True, stream=True)
        final_url = resp.url
        resp.close()

        if resp.history:
            has_redirects = True
            for hop in resp.history:
                chain.append({
                    "url": hop.url,
                    "status_code": hop.status_code
                })
            chain.append({
                "url": final_url,
                "status_code": resp.status_code
            })

            orig_host = (urlparse(raw_url).hostname or "").lower()
            final_host = (urlparse(final_url).hostname or "").lower()
            if orig_host and final_host and orig_host != final_host:
                cross_domain = True

    except Exception as e:
        return {
            "has_redirects": False,
            "redirect_count": 0,
            "final_url": raw_url,
            "chain": [],
            "cross_domain": False,
            "status": "unreachable",
            "note": f"Server unreachable or timed out during redirect probe."
        }

    return {
        "has_redirects": has_redirects,
        "redirect_count": len(chain) - 1 if chain else 0,
        "final_url": final_url,
        "chain": chain,
        "cross_domain": cross_domain,
        "status": "success",
        "note": (
            f"Redirect chain detected ({len(chain) - 1} hops): leads to {final_url}"
            if has_redirects else "Direct link (0 redirects)"
        )
    }
