from typing import List, Dict, Any, Optional

LEGIT_BRANDS: Dict[str, List[str]] = {
    "google": ["google.com", "google.co.uk", "google.ca", "google.org", "gmail.com", "youtube.com"],
    "microsoft": ["microsoft.com", "office.com", "live.com", "outlook.com", "azure.com", "xbox.com"],
    "paypal": ["paypal.com", "paypal.me"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "aws.amazon.com"],
    "facebook": ["facebook.com", "fb.com", "meta.com", "instagram.com", "whatsapp.com"],
    "apple": ["apple.com", "icloud.com"],
    "netflix": ["netflix.com"],
    "linkedin": ["linkedin.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "dropbox": ["dropbox.com"],
    "adobe": ["adobe.com"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "telegram": ["telegram.org", "t.me"],
    "roblox": ["roblox.com"],
    "ebay": ["ebay.com"],
    "walmart": ["walmart.com"],
    "usps": ["usps.com"],
    "fedex": ["fedex.com"],
    "dhl": ["dhl.com"]
}

HOMOGLYPH_MAP = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
    '7': 't', '8': 'b', '@': 'a', '$': 's', 'v': 'u'
}

def normalize_homoglyphs(text: str) -> str:
    res = text.lower()
    for char, replacement in HOMOGLYPH_MAP.items():
        res = res.replace(char, replacement)
    return res

def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) > len(s2):
        s1, s2 = s2, s1
    distances = range(len(s1) + 1)
    for i2, c2 in enumerate(s2):
        distances_ = [i2 + 1]
        for i1, c1 in enumerate(s1):
            if c1 == c2:
                distances_.append(distances[i1])
            else:
                distances_.append(1 + min((distances[i1], distances[i1 + 1], distances_[-1])))
        distances = distances_
    return distances[-1]

def calculate_similarity_ratio(s1: str, s2: str) -> float:
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0
    dist = levenshtein_distance(s1, s2)
    return max(0.0, 1.0 - (dist / max_len))

def detect_brand_impersonation(url_data: Dict[str, Any]) -> Dict[str, Any]:
    registered_domain = (url_data.get("registered_domain") or "").lower()
    domain_name = (url_data.get("domain") or "").lower()
    hostname = (url_data.get("hostname") or "").lower()
    subdomain = (url_data.get("subdomain") or "").lower()

    normalized_domain = normalize_homoglyphs(domain_name)
    normalized_host = normalize_homoglyphs(hostname)

    impersonation_detected = False
    impersonated_brand = None
    reason = None
    severity = "NONE"
    similarity_percentage = 0

    for brand, legit_domains in LEGIT_BRANDS.items():
        # Check if actual domain is legitimate
        is_legit = any(registered_domain == d or hostname == d or hostname.endswith("." + d) for d in legit_domains)
        if is_legit:
            continue

        # 1. Brand name directly embedded in an unrelated registered domain
        if brand in registered_domain:
            impersonation_detected = True
            impersonated_brand = brand
            similarity_percentage = 90
            reason = f"Brand '{brand}' found in unrelated registered domain '{registered_domain}'"
            severity = "HIGH"
            break

        # 2. Brand name in subdomain of an external service
        if brand in subdomain:
            impersonation_detected = True
            impersonated_brand = brand
            similarity_percentage = 85
            reason = f"Brand '{brand}' used in subdomain '{subdomain}' on non-{brand} domain '{registered_domain}'"
            severity = "HIGH"
            break

        # 3. Homoglyph substitution (e.g. g00gle.com, paypa1.com)
        if brand in normalized_domain or brand in normalized_host:
            impersonation_detected = True
            impersonated_brand = brand
            similarity_percentage = 95
            reason = f"Character substitution / homoglyph masquerading as '{brand}'"
            severity = "CRITICAL"
            break

        # 4. Typosquatting via Levenshtein distance
        if len(domain_name) >= 4 and abs(len(domain_name) - len(brand)) <= 2:
            dist = levenshtein_distance(domain_name, brand)
            if dist == 1:
                impersonation_detected = True
                impersonated_brand = brand
                similarity_percentage = int(calculate_similarity_ratio(domain_name, brand) * 100)
                reason = f"Typosquatting variation of '{brand}' (distance 1: '{domain_name}')"
                severity = "HIGH"
                break

    return {
        "impersonation_detected": impersonation_detected,
        "impersonated_brand": impersonated_brand,
        "reason": reason or "No typosquatting or brand impersonation found",
        "severity": severity,
        "similarity_percentage": similarity_percentage
    }
