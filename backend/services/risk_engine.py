from typing import Dict, Any, Tuple, List

def calculate_risk_score(signals: Dict[str, Any]) -> Tuple[int, str, bool, Dict[str, Any]]:
    """
    Combines multi-engine signals with deduplication and severity weighting.
    Returns: (final_score, risk_level, is_threat_confirmed, calculation_dossier)
    """
    breakdown_items: List[Dict[str, Any]] = []
    score = 0
    is_threat_confirmed = False

    # 1. Threat Intelligence confirmed matches (Primary authority)
    if signals.get("urlhaus_match"):
        points = 40
        score += points
        breakdown_items.append({
            "factor": "URLhaus Confirmed Threat",
            "points": points,
            "description": "Active malware distribution URL recorded in abuse.ch intelligence database."
        })
        is_threat_confirmed = True

    if signals.get("google_match"):
        points = 40
        score += points
        breakdown_items.append({
            "factor": "Google Safe Browsing Match",
            "points": points,
            "description": "Official Google Safe Browsing classification as social engineering or malware."
        })
        is_threat_confirmed = True

    vt_malicious = signals.get("virustotal_malicious_count", 0)
    vt_total = signals.get("virustotal_total_count", 60) or 60
    if vt_malicious > 0:
        vt_score = min(vt_malicious * 8, 35)
        score += vt_score
        breakdown_items.append({
            "factor": f"VirusTotal Multi-Vendor Detection ({vt_malicious}/{vt_total})",
            "points": vt_score,
            "description": f"{vt_malicious} out of {vt_total} independent antivirus and security engines flagged this URL."
        })
        if vt_malicious >= 3:
            is_threat_confirmed = True

    # 2. Structural & Domain Heuristics (URL scanner)
    if signals.get("punycode_threat"):
        points = 25
        score += points
        breakdown_items.append({
            "factor": "Punycode / Homoglyph Impersonation",
            "points": points,
            "description": "Domain employs Unicode homoglyphs or Punycode (xn--) to visually spoof a trusted hostname."
        })

    if signals.get("brand_impersonation"):
        points = 20
        score += points
        breakdown_items.append({
            "factor": "Brand Impersonation / Typosquatting",
            "points": points,
            "description": f"Target mimics a recognized corporate brand ({signals.get('impersonated_brand', 'brand')}) on an unrelated domain."
        })

    if signals.get("url_shortener"):
        points = 10
        score += points
        breakdown_items.append({
            "factor": f"URL Shortener Concealment ({signals.get('shortener_service', 'shortener')})",
            "points": points,
            "description": "Shortened link obscures the final target destination from visual inspection."
        })

    if signals.get("new_domain"):
        points = 10
        score += points
        breakdown_items.append({
            "factor": "Recently Registered Domain (<30 Days)",
            "points": points,
            "description": "Domain was registered within the past 30 days according to RDAP registry records."
        })

    # Direct IP handling (Private vs Public)
    if signals.get("ip_based"):
        if signals.get("is_private_ip"):
            points = 10
            score += points
            breakdown_items.append({
                "factor": "Direct Private IP Host (RFC 1918)",
                "points": points,
                "description": "URL targets an unroutable private network IP address (e.g., 192.168.x.x) rather than a public domain."
            })
        else:
            points = 15
            score += points
            breakdown_items.append({
                "factor": "Direct Public IP Host",
                "points": points,
                "description": "URL uses a raw public IP address without domain name registration or authoritative DNS."
            })

    # Subdomain spoofing
    if signals.get("subdomain_spoofing"):
        points = 30
        score += points
        breakdown_items.append({
            "factor": "Deceptive Financial Subdomain Spoofing",
            "points": points,
            "description": "Host uses a deceptive bank/security subdomain prefix on an unrelated or unverified domain."
        })

    # Insecure cleartext HTTP for sensitive portals
    if signals.get("is_http") and (signals.get("suspicious_keywords") or signals.get("brand_impersonation") or signals.get("subdomain_spoofing")):
        points = 25
        score += points
        breakdown_items.append({
            "factor": "Insecure Cleartext Protocol for Sensitive Target",
            "points": points,
            "description": "Target transmits login or banking authentication parameters over unencrypted cleartext HTTP."
        })

    # Keyword detection for URLs
    if signals.get("suspicious_keywords"):
        if signals.get("only_auth_keyword"):
            points = 1
            score += points
            breakdown_items.append({
                "factor": "Standard Authentication Path Token ('login')",
                "points": points,
                "description": "Standard login/signin keyword found in URL path. Normal for web portals; minimal risk contribution on its own."
            })
        else:
            kws = signals.get("detected_keywords", [])
            points = min(len(kws) * 8, 25)
            score += points
            breakdown_items.append({
                "factor": f"Deceptive Phishing / Financial Keywords ({len(kws)} detected)",
                "points": points,
                "description": f"High-risk terms detected: {', '.join(kws[:5])}"
            })

    # 3. Message & Social Engineering Phishing Heuristics
    if signals.get("explicit_secret_demand"):
        points = 35
        score += points
        breakdown_items.append({
            "factor": "Explicit Password / OTP / PIN Demand",
            "points": points,
            "description": "Text directly requests passwords, PINs, OTP codes, or secret recovery keys."
        })

    if signals.get("credential_verification_attempt"):
        points = 20
        score += points
        breakdown_items.append({
            "factor": "Account Credential Verification Attempt",
            "points": points,
            "description": "Coercive call-to-action urging immediate account or identity verification."
        })

    if signals.get("account_suspension_threat"):
        points = 20
        score += points
        breakdown_items.append({
            "factor": "Account Suspension / Coercion Threat",
            "points": points,
            "description": "Threatens immediate account closure, freezing, or legal penalty to induce panic."
        })

    if signals.get("suspicious_embedded_url"):
        url_points = signals.get("embedded_url_points", 30)
        score += url_points
        breakdown_items.append({
            "factor": "Suspicious / Private IP Embedded Link",
            "points": url_points,
            "description": f"Message contains an embedded link pointing to an unverified private network or high-risk destination ({signals.get('embedded_url_host', 'host')})."
        })

    if signals.get("artificial_urgency"):
        points = 10
        score += points
        breakdown_items.append({
            "factor": "Artificial Urgency & Countdown Pressure",
            "points": points,
            "description": "Imposes artificial deadlines to pressure victim into bypassing critical inspection."
        })

    if signals.get("unverified_security_identity"):
        points = 10
        score += points
        breakdown_items.append({
            "factor": "Unverified Security Identity",
            "points": points,
            "description": "Uses generic organizational title ('Security Department') without verifiable institution."
        })

    if signals.get("payment_request"):
        points = 25
        score += points
        breakdown_items.append({
            "factor": "Advance Fee / Monetary Payment Request",
            "points": points,
            "description": "Demands upfront payment, registration fee, or cryptocurrency transfer."
        })

    if signals.get("reply_to_mismatch"):
        points = 15
        score += points
        breakdown_items.append({
            "factor": "Reply-To Address Mismatch",
            "points": points,
            "description": "Reply-To header routes responses to a different email address than the sender."
        })

    if signals.get("suspicious_attachment"):
        points = 25
        score += points
        breakdown_items.append({
            "factor": "High-Risk Executable or Script Attachment",
            "points": points,
            "description": "Attached file contains dangerous file extension (.exe, .scr, .iso, .zip, .vbs)."
        })

    if signals.get("fake_recruitment"):
        points = 15
        score += points
        breakdown_items.append({
            "factor": "Suspicious Hiring Conditions",
            "points": points,
            "description": "Unrealistic hiring terms such as guaranteed selection without interview."
        })

    if signals.get("unofficial_sender"):
        points = 10
        score += points
        breakdown_items.append({
            "factor": "Public Webmail Sender Mismatch",
            "points": points,
            "description": "Sender claims corporate affiliation but contacts from a free public webmail service."
        })

    # 4. AI Forensics Blend
    ai_score = signals.get("ai_score", 0)
    if ai_score >= 70:
        ai_contribution = min(int(ai_score * 0.35), 30)
        score += ai_contribution
        breakdown_items.append({
            "factor": "AI Contextual Forensics (High Risk Phishing Intent)",
            "points": ai_contribution,
            "description": f"Groq AI intent model scored {ai_score}/100 detecting deceptive phishing or credential theft patterns."
        })
    elif ai_score > 0 and score < 70:
        ai_contribution = min(int(ai_score * 0.3), 20)
        if ai_contribution > 0:
            score += ai_contribution
            breakdown_items.append({
                "factor": "AI Contextual Forensics Blend",
                "points": ai_contribution,
                "description": "Machine learning intent analysis evaluated language patterns, urgency, and structural context."
            })

    # Bound between 0 and 100
    final_score = min(max(score, 0), 100)

    if final_score >= 70:
        risk_level = "HIGH"
    elif final_score >= 40:
        risk_level = "SUSPICIOUS"
    elif final_score >= 20:
        risk_level = "CAUTION"
    else:
        risk_level = "LOW"

    dossier = {
        "final_score": final_score,
        "risk_level": risk_level,
        "is_threat_confirmed": is_threat_confirmed,
        "calculation_items": breakdown_items,
        "formula": f"Sum of {len(breakdown_items)} validated risk indicators = {final_score}/100"
    }

    return final_score, risk_level, is_threat_confirmed, dossier
