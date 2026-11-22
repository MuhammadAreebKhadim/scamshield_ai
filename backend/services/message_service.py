import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, Optional, List
from backend.detectors.email_detector import analyze_text_patterns
from backend.ai.message_analyzer import analyze_with_ai
from backend.services.risk_engine import calculate_risk_score
from backend.services.url_service import scan_url_service
from backend.services.consistency_validator import validate_and_reconcile_report
from backend.database.models import ScanRecord
from backend.database.connection import db

def scan_message_service(
    content: str,
    channel: str = "Email",
    user_id: Optional[str] = None,
    user_email: Optional[str] = None
) -> ScanRecord:
    pattern_res = analyze_text_patterns(content)
    extracted_urls = pattern_res.get("extracted_urls", [])

    # Parallelize AI inspection and embedded URL scans
    with ThreadPoolExecutor(max_workers=5) as executor:
        ai_future = executor.submit(
            analyze_with_ai, content, f"{channel} message", {"channel": channel}
        )

        url_futures = []
        for u in extracted_urls[:3]:  # Scan up to 3 embedded URLs
            url_futures.append(executor.submit(scan_url_service, u, user_id, user_email))

        try:
            ai_res = ai_future.result(timeout=14)
        except Exception:
            ai_res = {
                "risk_score": 10,
                "risk_level": "LOW",
                "indicators": [],
                "highlighted_sentences": [],
                "recommendation": "Review message contents carefully."
            }

        url_scans: List[ScanRecord] = []
        for uf in url_futures:
            try:
                res = uf.result(timeout=10)
                if isinstance(res, ScanRecord):
                    url_scans.append(res)
            except Exception:
                pass

    # Extract rich telemetry for each embedded URL
    embedded_url_analyses: List[Dict[str, Any]] = []
    has_suspicious_embedded_url = False
    embedded_url_points = 0
    highest_embedded_host = ""

    threat_intel_result = {}
    for us in url_scans:
        u_input_data = us.input_data or {}
        ip_check = u_input_data.get("ip_check", {})
        protocol_analysis = u_input_data.get("protocol_analysis", {})
        dns_records = u_input_data.get("dns_records", {})

        url_summary = {
            "url": us.input_summary,
            "risk_score": us.risk_score,
            "risk_level": us.risk_level,
            "is_threat_confirmed": us.is_threat_confirmed,
            "protocol": protocol_analysis.get("protocol", "HTTP"),
            "is_https": protocol_analysis.get("is_https", False),
            "ip_classification": ip_check.get("ip_classification", "Domain Host"),
            "is_private_ip": ip_check.get("is_private", False),
            "is_ip": ip_check.get("is_ip", False),
            "dns_status": dns_records.get("dns_status", "N/A"),
            "findings": [ind.get("name") for ind in us.indicators[:3]],
            "threat_intelligence": us.threat_intelligence or {}
        }
        embedded_url_analyses.append(url_summary)

        # Flag suspicious links (Private IP, score >= 30, or confirmed threat)
        if ip_check.get("is_private") or ip_check.get("is_ip") or us.risk_score >= 30:
            has_suspicious_embedded_url = True
            embedded_url_points = max(embedded_url_points, 35 if us.risk_score >= 70 or ip_check.get("is_private") else 25)
            highest_embedded_host = us.input_summary

        if us.threat_intelligence and not threat_intel_result:
            threat_intel_result = us.threat_intelligence

    # Assemble preliminary signals for scoring engine
    signals: Dict[str, Any] = {
        "explicit_secret_demand": pattern_res.get("has_explicit_secret_demand", False),
        "credential_verification_attempt": pattern_res.get("has_credential_verification", False),
        "account_suspension_threat": pattern_res.get("has_suspension_threat", False),
        "artificial_urgency": pattern_res.get("has_urgency", False),
        "unverified_security_identity": pattern_res.get("has_generic_authority", False),
        "brand_impersonation": pattern_res.get("has_brand_impersonation", False),
        "payment_request": pattern_res.get("has_payment_demand", False),
        "reply_to_mismatch": pattern_res.get("reply_to_mismatch", False),
        "suspicious_attachment": pattern_res.get("has_suspicious_attachment", False),
        "fake_recruitment": pattern_res.get("has_unrealistic_lures", False),
        "suspicious_embedded_url": has_suspicious_embedded_url,
        "embedded_url_points": embedded_url_points,
        "embedded_url_host": highest_embedded_host,
        "ai_score": ai_res.get("risk_score", 0),
        "urlhaus_match": False,
        "google_match": False,
        "virustotal_malicious_count": 0
    }

    # Build preliminary indicators
    preliminary_indicators: List[Dict[str, Any]] = []

    # 1. Embedded URLs
    for eu in embedded_url_analyses:
        if eu.get("is_private_ip"):
            preliminary_indicators.append({
                "name": "Embedded Link (Private IP Host)",
                "evidence": f"Link '{eu['url']}' targets private unroutable IP (RFC 1918). URL Score: {eu['risk_score']}/100 ({eu['risk_level']}), Protocol: {eu['protocol']}.",
                "severity": "CRITICAL",
                "category": "Embedded Link Analysis"
            })
        elif eu.get("risk_score", 0) >= 40:
            preliminary_indicators.append({
                "name": "High-Risk Embedded URL",
                "evidence": f"Link '{eu['url']}' scored {eu['risk_score']}/100 ({eu['risk_level']}). Protocol: {eu['protocol']}.",
                "severity": "CRITICAL" if eu.get("risk_score", 0) >= 70 else "HIGH",
                "category": "Embedded Link Analysis"
            })
        elif eu.get("is_ip"):
            preliminary_indicators.append({
                "name": "Direct IP Embedded URL",
                "evidence": f"Link '{eu['url']}' uses raw IP address rather than authenticated domain.",
                "severity": "HIGH",
                "category": "Embedded Link Analysis"
            })

    # 2. Credential Theft / Verification
    if pattern_res.get("has_explicit_secret_demand"):
        preliminary_indicators.append({
            "name": "Explicit Credential / Password Request",
            "evidence": "Direct solicitation of secret credentials (passwords, PINs, OTP codes, or CNIC).",
            "severity": "CRITICAL",
            "category": "Credential Harvesting"
        })
    elif pattern_res.get("has_credential_verification"):
        preliminary_indicators.append({
            "name": "Account Credential Verification Attempt",
            "evidence": "Message demands account or identity verification ('verify your account immediately'). Explicit password or PIN request was not directly present in text, but link targets credential collection.",
            "severity": "HIGH",
            "category": "Credential Harvesting"
        })

    # 3. Account Suspension & Coercion
    if pattern_res.get("has_suspension_threat"):
        preliminary_indicators.append({
            "name": "Account Suspension / Coercion Threat",
            "evidence": "Coercive warning that account will be suspended, blocked, or terminated if immediate action is not taken.",
            "severity": "HIGH",
            "category": "Social Engineering"
        })

    # 4. Artificial Urgency
    if pattern_res.get("has_urgency"):
        preliminary_indicators.append({
            "name": "Artificial Urgency & Countdown Pressure",
            "evidence": "Imposes tight deadlines or urgent wording designed to bypass rational security evaluation.",
            "severity": "MEDIUM",
            "category": "Social Engineering"
        })

    # 5. Security Department / Unverified Authority
    if pattern_res.get("has_generic_authority"):
        preliminary_indicators.append({
            "name": "Unverified Security Identity",
            "evidence": "Sender employs generic title ('Security Department') to assert institutional authority without verifiable organization name.",
            "severity": "MEDIUM",
            "category": "Identity Verification"
        })

    # 6. Named Brand Impersonation
    if pattern_res.get("has_brand_impersonation"):
        preliminary_indicators.append({
            "name": "Brand / Agency Impersonation",
            "evidence": "Sender explicitly claims affiliation with recognized financial institution, government body, or enterprise brand.",
            "severity": "HIGH",
            "category": "Identity Verification"
        })

    # 7. Payment Demand
    if pattern_res.get("has_payment_demand"):
        preliminary_indicators.append({
            "name": "Financial Payment / Advance Fee Demand",
            "evidence": "Demands direct monetary transfer, processing fee, or cryptocurrency payment.",
            "severity": "CRITICAL",
            "category": "Financial Fraud"
        })

    # 8. Suspicious Attachment
    if pattern_res.get("has_suspicious_attachment"):
        preliminary_indicators.append({
            "name": "High-Risk Executable or Script Attachment",
            "evidence": f"Detected dangerous file extension: {', '.join(pattern_res['header_analysis'].get('suspicious_attachments', []))}",
            "severity": "HIGH",
            "category": "Attachment Analysis"
        })

    # 9. Reply-To Mismatch
    if pattern_res.get("reply_to_mismatch"):
        preliminary_indicators.append({
            "name": "Reply-To Address Mismatch",
            "evidence": f"Reply-To ({pattern_res['header_analysis'].get('reply_to_email')}) differs from sender From ({pattern_res['header_analysis'].get('sender_email')}).",
            "severity": "HIGH",
            "category": "Header Forensics"
        })

    # 10. AI Indicators
    for ind in ai_res.get("indicators", []):
        preliminary_indicators.append({
            "name": ind.get("name", "AI Indicator"),
            "evidence": ind.get("evidence", ""),
            "severity": ind.get("severity", "MEDIUM"),
            "category": "AI Forensic Engine"
        })

    # Calculate raw score from multi-engine rules
    raw_score, raw_level, is_threat_confirmed, breakdown = calculate_risk_score(signals)
    breakdown_items = breakdown.get("calculation_items", [])

    preliminary_recommendations = []

    # Apply the Consistency Validation Layer
    (
        final_score,
        final_level,
        final_recommendations,
        reconciled_indicators,
        reconciled_breakdown_items,
        validation_summary
    ) = validate_and_reconcile_report(
        input_type="message",
        risk_score=raw_score,
        risk_level=raw_level,
        indicators=preliminary_indicators,
        breakdown_items=breakdown_items,
        recommendations=preliminary_recommendations,
        pattern_data=pattern_res,
        embedded_url_scans=url_scans
    )

    # Compile sentence highlights
    all_highlights = []
    seen_texts = set()
    for h in pattern_res.get("flagged_sentences", []):
        if h["text"] not in seen_texts:
            seen_texts.add(h["text"])
            all_highlights.append(h)

    for h in ai_res.get("highlighted_sentences", []):
        if h.get("text") and h["text"] not in seen_texts:
            seen_texts.add(h["text"])
            all_highlights.append(h)

    scan_id = f"SC-{uuid.uuid4().hex[:6].upper()}"
    ai_res["highlighted_sentences"] = all_highlights

    # Reassemble score breakdown with reconciled items
    reconciled_breakdown = {
        "final_score": final_score,
        "risk_level": final_level,
        "is_threat_confirmed": is_threat_confirmed or final_score >= 70,
        "calculation_items": reconciled_breakdown_items,
        "formula": f"Sum of {len(reconciled_breakdown_items)} validated risk indicators = {final_score}/100"
    }

    scan_record = ScanRecord(
        scan_id=scan_id,
        user_id=user_id or "anonymous",
        user_email=user_email or "anonymous@scamshield.ai",
        input_type="message",
        input_summary=content[:100] + ("..." if len(content) > 100 else ""),
        input_data={
            "content": content,
            "channel": channel,
            "pattern_matches": pattern_res.get("matched_categories", {}),
            "extracted_urls": extracted_urls,
            "embedded_url_analyses": embedded_url_analyses,
            "header_analysis": pattern_res.get("header_analysis", {}),
            "social_engineering": pattern_res.get("social_engineering", {}),
            "validation_summary": validation_summary,
            "flagged_count": len(all_highlights)
        },
        risk_score=final_score,
        risk_level=final_level,
        is_threat_confirmed=is_threat_confirmed or final_score >= 70,
        indicators=reconciled_indicators,
        threat_intelligence=threat_intel_result,
        ai_analysis=ai_res,
        recommendations=final_recommendations,
        score_breakdown=reconciled_breakdown
    )

    return db.save_scan(scan_record)
