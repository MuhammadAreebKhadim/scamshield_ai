import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, Optional, List
from backend.detectors.url_parser import parse_url_structure
from backend.detectors.keyword_detector import detect_suspicious_keywords
from backend.detectors.brand_detector import detect_brand_impersonation
from backend.detectors.ip_detector import detect_ip_based_url
from backend.detectors.domain_age import check_domain_age
from backend.detectors.shortener_detector import detect_url_shortener
from backend.detectors.punycode_detector import detect_punycode_and_homoglyphs
from backend.detectors.redirect_analyzer import analyze_redirect_chain
from backend.detectors.dns_analyzer import analyze_dns_records
from backend.intelligence.urlhaus import check_urlhaus
from backend.intelligence.virustotal import check_virustotal
from backend.intelligence.google_safe_browsing import check_google_safe_browsing
from backend.ai.message_analyzer import analyze_with_ai
from backend.services.risk_engine import calculate_risk_score
from backend.database.models import ScanRecord, Indicator
from backend.database.connection import db

def scan_url_service(url: str, user_id: Optional[str] = None, user_email: Optional[str] = None) -> ScanRecord:
    url_data = parse_url_structure(url)
    target_url = url_data["raw_url"]
    domain = url_data["registered_domain"] or url_data["hostname"]

    kw_result = detect_suspicious_keywords(url_data)
    brand_result = detect_brand_impersonation(url_data)
    ip_result = detect_ip_based_url(url_data)
    shortener_result = detect_url_shortener(url_data)
    punycode_result = detect_punycode_and_homoglyphs(url_data)

    # Parallelize external network lookups
    with ThreadPoolExecutor(max_workers=7) as executor:
        urlhaus_future = executor.submit(check_urlhaus, target_url)
        vt_future = executor.submit(check_virustotal, target_url)
        gsb_future = executor.submit(check_google_safe_browsing, target_url)
        age_future = executor.submit(check_domain_age, domain)
        dns_future = executor.submit(analyze_dns_records, url_data)
        redirect_future = executor.submit(analyze_redirect_chain, target_url, url_data)
        ai_future = executor.submit(
            analyze_with_ai,
            f"URL: {target_url}\nDomain: {domain}\nPath: {url_data['path']}\nIP Info: {ip_result.get('ip_classification')}",
            "url",
            {"domain": domain, "brand_check": brand_result, "ip_check": ip_result}
        )

        try:
            urlhaus_res = urlhaus_future.result(timeout=10)
        except Exception:
            urlhaus_res = {"status": "unavailable", "is_malicious": False}

        try:
            vt_res = vt_future.result(timeout=10)
        except Exception:
            vt_res = {"status": "unavailable", "malicious": 0, "total_vendors": 60, "is_malicious": False}

        try:
            gsb_res = gsb_future.result(timeout=10)
        except Exception:
            gsb_res = {"status": "unavailable", "is_threat_found": False}

        try:
            age_res = age_future.result(timeout=7)
        except Exception:
            age_res = {
                "status": "unavailable",
                "age_days": None,
                "is_new": False,
                "message": "Unavailable — Registration data not retrieved."
            }

        try:
            dns_res = dns_future.result(timeout=5)
        except Exception:
            dns_res = {"resolved": False, "dns_status": "DNS Lookup Unavailable", "resolved_ips": []}

        try:
            redirect_res = redirect_future.result(timeout=6)
        except Exception:
            redirect_res = {"has_redirects": False, "redirect_count": 0, "chain": [], "note": "Redirect check unavailable"}

        try:
            ai_res = ai_future.result(timeout=12)
        except Exception:
            ai_res = {
                "risk_score": 5,
                "risk_level": "LOW",
                "indicators": [],
                "highlighted_sentences": [],
                "recommendation": "Review URL context and certificate authenticity before submission."
            }

    indicators: List[Dict[str, Any]] = []
    vt_malicious = vt_res.get("malicious", 0)
    vt_total = vt_res.get("total_vendors", 60) or 60

    subdomain_str = (url_data.get("subdomain") or "").lower()
    subdomain_spoofing = (brand_result["impersonation_detected"] and bool(subdomain_str)) or any(
        tok in subdomain_str for tok in ["bank", "verify", "verification", "secure", "login", "signin", "account", "claim", "prize", "update", "security", "auth", "support"]
    )
    is_http_insecure = not url_data.get("is_https", True)

    FINANCIAL_TOKENS = ["bank", "banking", "creditcard", "debitcard", "wire", "wallet", "kyc", "tax", "irs", "payout", "payroll", "invoice", "payment", "billing", "chase", "wellsfargo", "bofa", "citibank", "secure-bank"]
    URGENCY_ACTION_TOKENS = ["verify", "verification", "secure", "security", "confirm", "confirmation", "suspended", "unusual-activity", "update", "unlock", "restore", "reactivate", "auth", "2fa", "password", "pin", "credential", "security-alert", "helpdesk"]
    PRIZE_SCAM_TOKENS = ["claim-prize", "claim", "prize", "lottery", "winner", "winning", "lucky", "giveaway", "airdrop", "reward", "jackpot", "congratulations", "free-gift", "claim-now"]

    full_target_lower = f"{url_data.get('hostname', '').lower()}{url_data.get('path', '').lower()}"
    det_financial = [t for t in FINANCIAL_TOKENS if t in full_target_lower]
    det_urgency = [t for t in URGENCY_ACTION_TOKENS if t in full_target_lower]
    det_prize = [t for t in PRIZE_SCAM_TOKENS if t in full_target_lower]

    is_financial_phishing = len(det_financial) > 0 and (len(det_urgency) > 0 or subdomain_spoofing)
    is_prize_scam = len(det_prize) > 0 and (len(det_financial) > 0 or len(det_urgency) > 0 or is_http_insecure)

    host_parts = url_data.get("hostname", "").lower().split("-")
    compound_triggers = [p for p in host_parts if any(f in p for f in FINANCIAL_TOKENS + URGENCY_ACTION_TOKENS + PRIZE_SCAM_TOKENS)]
    has_compound_deception = len(compound_triggers) >= 2

    signals: Dict[str, Any] = {
        "urlhaus_match": urlhaus_res.get("is_malicious", False),
        "google_match": gsb_res.get("is_threat_found", False),
        "virustotal_malicious_count": vt_malicious,
        "virustotal_total_count": vt_total,
        "brand_impersonation": brand_result["impersonation_detected"],
        "impersonated_brand": brand_result.get("impersonated_brand"),
        "brand_severity": brand_result.get("severity", "NONE"),
        "punycode_threat": punycode_result["is_suspicious_homoglyph"],
        "url_shortener": shortener_result["is_shortened"],
        "shortener_service": shortener_result.get("service"),
        "new_domain": age_res.get("is_new", False),
        "suspicious_keywords": kw_result["has_suspicious_keywords"] or len(kw_result["detected_keywords"]) > 0,
        "only_auth_keyword": kw_result.get("only_auth_keyword", False),
        "detected_keywords": kw_result.get("detected_keywords", []),
        "ip_based": ip_result["is_ip"],
        "is_private_ip": ip_result.get("is_private", False),
        "subdomain_spoofing": subdomain_spoofing,
        "is_http": is_http_insecure,
        "is_financial_phishing": is_financial_phishing,
        "is_prize_scam": is_prize_scam,
        "has_compound_deception": has_compound_deception,
        "ai_score": ai_res.get("risk_score", 0)
    }

    # 1. Threat Intel Indicators
    if urlhaus_res.get("is_malicious"):
        indicators.append({
            "name": "Confirmed Malware Distribution",
            "evidence": f"URLhaus flagged threat: {urlhaus_res.get('threat', 'malware')} (tags: {', '.join(urlhaus_res.get('tags', []))})",
            "severity": "CRITICAL",
            "category": "Threat Intelligence"
        })

    if gsb_res.get("is_threat_found"):
        threat_types = gsb_res.get("threat_types", [])
        indicators.append({
            "name": "Google Safe Browsing Match",
            "evidence": f"Flagged by Google Safe Browsing as unsafe ({', '.join(threat_types)})",
            "severity": "CRITICAL",
            "category": "Threat Intelligence"
        })

    if vt_malicious > 0:
        indicators.append({
            "name": "Multi-Vendor Security Flags",
            "evidence": f"{vt_malicious}/{vt_total} security vendors flagged this URL on VirusTotal",
            "severity": "HIGH" if vt_malicious >= 3 else "MEDIUM",
            "category": "Threat Intelligence"
        })

    # 2. Punycode & Homoglyph Attacks
    if punycode_result["is_suspicious_homoglyph"]:
        indicators.append({
            "name": "Punycode / Homoglyph Impersonation",
            "evidence": punycode_result["warning"],
            "severity": "HIGH",
            "category": "Domain Heuristics"
        })

    # 3. Brand Impersonation & Typosquatting
    if brand_result["impersonation_detected"]:
        indicators.append({
            "name": "Brand Impersonation Detected",
            "evidence": f"{brand_result['reason']} (Similarity match: {brand_result.get('similarity_percentage', 0)}%)",
            "severity": brand_result["severity"],
            "category": "Domain Heuristics"
        })

    if subdomain_spoofing:
        indicators.append({
            "name": "Deceptive Financial Subdomain Spoofing",
            "evidence": f"Subdomain '{url_data.get('subdomain')}' mimics high-trust banking/verification portals on domain '{domain}'.",
            "severity": "CRITICAL",
            "category": "Domain Heuristics"
        })

    if is_http_insecure and (signals.get("suspicious_keywords") or subdomain_spoofing or brand_result["impersonation_detected"]):
        indicators.append({
            "name": "Cleartext HTTP on Sensitive Portal",
            "evidence": "Target transmits credential and security verification data over unencrypted cleartext HTTP.",
            "severity": "HIGH",
            "category": "Protocol Analysis"
        })

    # 4. URL Shortener
    if shortener_result["is_shortened"]:
        indicators.append({
            "name": "URL Shortener Concealment",
            "evidence": shortener_result["warning"],
            "severity": "MEDIUM",
            "category": "URL Structure"
        })

    # 5. Direct IP (Private vs Public distinction)
    if ip_result["is_ip"]:
        if ip_result.get("is_private"):
            indicators.append({
                "name": "Direct IP Host (Private Network)",
                "evidence": f"URL targets a private IP ({url_data['hostname']}, RFC 1918). Unroutable from public internet; typical of local router admin portals or internal network targeting.",
                "severity": "MEDIUM",
                "category": "Host Analysis"
            })
        else:
            indicators.append({
                "name": "Direct IP Host Usage",
                "evidence": f"URL points to a raw public IP address ({url_data['hostname']}) rather than an authenticated domain name.",
                "severity": "HIGH",
                "category": "Host Analysis"
            })

    # 6. Domain Age
    if age_res.get("is_new"):
        indicators.append({
            "name": "Recently Registered Domain",
            "evidence": age_res.get("message", "Registered less than 30 days ago"),
            "severity": "HIGH",
            "category": "Domain Age"
        })

    # 7. Keywords (with minimal penalty if standard login)
    if kw_result.get("only_auth_keyword"):
        indicators.append({
            "name": "Authentication Path Indicator",
            "evidence": "Standard 'login' authentication path token in URL. Common for web portals; minimal risk contribution on its own.",
            "severity": "LOW",
            "category": "URL Structure"
        })
    elif kw_result.get("has_suspicious_keywords"):
        indicators.append({
            "name": "Suspicious Keyword Triggers",
            "evidence": f"Keywords detected: {', '.join(kw_result['detected_keywords'])}",
            "severity": "MEDIUM",
            "category": "URL Structure"
        })

    # 8. DNS Resolution Warnings
    if not dns_res.get("is_direct_ip") and not dns_res.get("resolved"):
        indicators.append({
            "name": "Unresolved DNS Domain (NXDOMAIN)",
            "evidence": dns_res.get("message", "Domain does not resolve to active IP infrastructure."),
            "severity": "MEDIUM",
            "category": "DNS Records"
        })

    # 9. Redirect Chain Warnings
    if redirect_res.get("has_redirects") and redirect_res.get("cross_domain"):
        indicators.append({
            "name": "Cross-Domain Redirect Chain",
            "evidence": f"URL redirects across different domains ({redirect_res.get('redirect_count')} hops) to final destination: {redirect_res.get('final_url')}",
            "severity": "MEDIUM",
            "category": "Redirect Analysis"
        })

    # 10. AI Indicators
    for ind in ai_res.get("indicators", []):
        indicators.append({
            "name": ind.get("name", "AI Indicator"),
            "evidence": ind.get("evidence", ""),
            "severity": ind.get("severity", "MEDIUM"),
            "category": "AI Contextual Forensics"
        })

    # Calculate overall risk score and calculation explanation breakdown
    risk_score, risk_level, is_threat_confirmed, breakdown = calculate_risk_score(signals)

    # Dynamic Defensive Recommendations
    recommendations = []
    if risk_score >= 70 or is_threat_confirmed:
        recommendations.append("Do NOT visit or input any personal, banking, or corporate credentials on this target.")
        recommendations.append("Block and blacklist this endpoint immediately across network firewalls.")
    elif risk_score >= 40:
        recommendations.append("Exercise extreme caution. Verify the destination hostname independently before interacting.")
        recommendations.append("Never submit passwords or sensitive documents on this webpage.")
    elif ip_result.get("is_private"):
        recommendations.append("Private IP target: If this is your local router or device, verify you are on your trusted home/office network.")
        recommendations.append("Never enter sensitive corporate credentials into unverified internal IP web interfaces.")
    else:
        recommendations.append("No active malicious signatures detected. Always ensure HTTPS connection is present.")

    # Always append HTTPS advisory
    if not url_data.get("is_https"):
        recommendations.append("Caution: Connection uses unencrypted HTTP. Data transmitted in cleartext without TLS encryption.")
    else:
        recommendations.append("Note: Valid HTTPS encrypts transmission in transit, but does not verify website authenticity.")

    scan_id = f"SC-{uuid.uuid4().hex[:6].upper()}"

    scan_record = ScanRecord(
        scan_id=scan_id,
        user_id=user_id or "anonymous",
        user_email=user_email or "anonymous@scamshield.ai",
        input_type="url",
        input_summary=target_url,
        input_data={
            "url": target_url,
            "url_structure": url_data,
            "protocol_analysis": url_data.get("protocol_analysis"),
            "domain_age": age_res,
            "brand_check": brand_result,
            "ip_check": ip_result,
            "keywords": kw_result,
            "shortener": shortener_result,
            "punycode": punycode_result,
            "dns_records": dns_res,
            "redirects": redirect_res
        },
        risk_score=risk_score,
        risk_level=risk_level,
        is_threat_confirmed=is_threat_confirmed,
        indicators=indicators,
        threat_intelligence={
            "urlhaus": urlhaus_res,
            "virustotal": vt_res,
            "google_safe_browsing": gsb_res
        },
        ai_analysis=ai_res,
        recommendations=recommendations,
        score_breakdown=breakdown
    )

    return db.save_scan(scan_record)
