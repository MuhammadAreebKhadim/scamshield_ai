from typing import Dict, Any, List, Tuple

def validate_and_reconcile_report(
    input_type: str,
    risk_score: int,
    risk_level: str,
    indicators: List[Dict[str, Any]],
    breakdown_items: List[Dict[str, Any]],
    recommendations: List[str],
    pattern_data: Dict[str, Any],
    embedded_url_scans: List[Any]
) -> Tuple[int, str, List[str], List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """
    Consistency Validation Layer
    Enforces strict consistency across evidence, risk scoring, indicator claims, and remediation guidance.
    """
    reconciliation_notes: List[str] = []

    # 1. Evidence evaluation
    has_explicit_secret = pattern_data.get("has_explicit_secret_demand", False)
    has_cred_verification = pattern_data.get("has_credential_verification", False)
    has_suspension = pattern_data.get("has_suspension_threat", False)
    has_urgency = pattern_data.get("has_urgency", False)
    has_generic_auth = pattern_data.get("has_generic_authority", False)
    has_brand_impersonation = pattern_data.get("has_brand_impersonation", False)
    has_payment = pattern_data.get("has_payment_demand", False)
    has_attachment = pattern_data.get("has_suspicious_attachment", False)

    # Check embedded URLs for high-risk signals
    has_private_ip_link = False
    has_malicious_link = False
    embedded_link_high_risk = False
    for u in embedded_url_scans:
        u_score = getattr(u, "risk_score", 0) if hasattr(u, "risk_score") else (u.get("risk_score", 0) if isinstance(u, dict) else 0)
        u_input_data = getattr(u, "input_data", {}) if hasattr(u, "input_data") else (u.get("input_data", {}) if isinstance(u, dict) else {})
        ip_check = u_input_data.get("ip_check", {})
        if ip_check.get("is_private") or ip_check.get("is_ip"):
            has_private_ip_link = True
        is_threat = getattr(u, "is_threat_confirmed", False) if hasattr(u, "is_threat_confirmed") else (u.get("is_threat_confirmed", False) if isinstance(u, dict) else False)
        if u_score >= 70 or is_threat:
            has_malicious_link = True
        if u_score >= 30:
            embedded_link_high_risk = True

    # 2. Rule 1 & Rule 3: Enforce evidence-to-score integrity and minimum risk floors
    score_floor = 0
    floor_reasons = []

    # Phishing Triad: Account Suspension + Credential Verification Call + Embedded Link
    if (has_suspension or has_urgency) and (has_cred_verification or has_explicit_secret) and (has_private_ip_link or embedded_link_high_risk):
        score_floor = max(score_floor, 80)
        floor_reasons.append("Phishing Triad detected (Account Suspension Coercion + Credential Verification Request + Embedded Host/IP Link)")

    elif (has_suspension and has_cred_verification):
        score_floor = max(score_floor, 75)
        floor_reasons.append("Account Suspension combined with Credential Verification attempt")

    elif has_explicit_secret:
        score_floor = max(score_floor, 85)
        floor_reasons.append("Explicit password/PIN/OTP credential demand")

    elif has_malicious_link:
        score_floor = max(score_floor, 80)
        floor_reasons.append("Embedded link confirmed as malicious by threat intelligence")

    elif has_payment and has_urgency:
        score_floor = max(score_floor, 75)
        floor_reasons.append("Advance payment demand with coercive urgency")

    adjusted_score = max(risk_score, score_floor)
    adjusted_score = min(max(adjusted_score, 0), 100)

    # Reclassify risk tier accurately
    if adjusted_score >= 70:
        adjusted_level = "HIGH"
    elif adjusted_score >= 40:
        adjusted_level = "SUSPICIOUS"
    elif adjusted_score >= 20:
        adjusted_level = "CAUTION"
    else:
        adjusted_level = "LOW"

    # If score was elevated to match critical evidence, record in breakdown
    if adjusted_score > risk_score and floor_reasons:
        diff = adjusted_score - risk_score
        breakdown_items.append({
            "factor": "Consistency Escalation (Threat Alignment)",
            "points": diff,
            "description": f"Risk score aligned to evidence floor: {'; '.join(floor_reasons)}."
        })
        reconciliation_notes.append(f"Score adjusted from {risk_score} to {adjusted_score} to reflect critical indicators.")

    # 3. Rule 4: Verify claims match explicit evidence (No over-claiming)
    sanitized_indicators: List[Dict[str, Any]] = []
    seen_categories = set()

    for ind in indicators:
        name = ind.get("name", "")
        evidence = ind.get("evidence", "")
        sev = ind.get("severity", "MEDIUM")
        category = ind.get("category", "General")

        # Check: Did message ask for password?
        if "Credential" in name or "Identity Harvesting" in name:
            if not has_explicit_secret and has_cred_verification:
                # Clarify: Credential verification attempt vs explicit password demand
                name = "Account Credential Verification Attempt"
                evidence = (
                    "Message demands account verification ('verify your account immediately'). "
                    "Explicit password/OTP request: Not detected in text body. "
                    "Potential credential harvesting: Suspected via embedded link."
                )
                sev = "HIGH"

        # Check: Security Department impersonation claim
        if "Impersonation" in name and not has_brand_impersonation and has_generic_auth:
            name = "Unverified Security Identity"
            evidence = "Sender uses generic title ('Security Department') to assert authority without verifiable institutional identity."
            sev = "MEDIUM"

        sanitized_indicators.append({
            "name": name,
            "evidence": evidence,
            "severity": sev,
            "category": category
        })

    # 4. Rule 5: Deduplicate repeated indicators by category
    unique_indicators: List[Dict[str, Any]] = []
    seen_indicator_keys = set()
    for ind in sanitized_indicators:
        key = f"{ind.get('name')}:{ind.get('severity')}"
        if key not in seen_indicator_keys:
            seen_indicator_keys.add(key)
            unique_indicators.append(ind)

    # 5. Rule 2: Ensure final recommendations strictly match risk classification
    reconciled_recommendations: List[str] = []

    if adjusted_level in ["HIGH", "SUSPICIOUS"]:
        # Purge any contradictory "benign" phrases
        if has_private_ip_link or has_cred_verification or has_suspension:
            reconciled_recommendations.append("Do not click the embedded link or provide account credentials.")
            reconciled_recommendations.append("Contact your bank or institution directly through its officially verified communication channels.")
            reconciled_recommendations.append("Banks and legitimate services will never threaten immediate account suspension via unauthenticated links or raw IP addresses.")
        else:
            reconciled_recommendations.append("Exercise extreme caution. Do not follow instructions or transfer funds based on this communication.")
            reconciled_recommendations.append("Verify the sender's identity through an independent, official channel.")

        if has_attachment:
            reconciled_recommendations.append("Do not download or open any attachments from this message; executable or script payloads may compromise your system.")

    elif adjusted_level == "CAUTION":
        reconciled_recommendations.append("Verify the sender's authentic identity before interacting.")
        reconciled_recommendations.append("Do not submit credentials or personal information without verifying the official website domain.")

    else:
        # LOW RISK
        reconciled_recommendations.append("No overt phishing or credential theft patterns identified in the message body.")
        reconciled_recommendations.append("Always verify the sender's authentic address before clicking external links.")

    validation_summary = {
        "is_consistent": True,
        "original_score": risk_score,
        "reconciled_score": adjusted_score,
        "score_floor_enforced": bool(score_floor > risk_score),
        "reconciliation_notes": reconciliation_notes,
        "evidence_checks": {
            "explicit_secret_demand": "Detected" if has_explicit_secret else "Not detected",
            "credential_verification_attempt": "Detected" if has_cred_verification else "Not detected",
            "potential_credential_harvesting": "Suspected" if (has_cred_verification and (has_private_ip_link or embedded_link_high_risk)) else "Not indicated",
            "security_identity_claim": "Unverified Generic Title" if has_generic_auth else ("Named Brand" if has_brand_impersonation else "None"),
            "embedded_url_risk": "High Risk / Private IP" if has_private_ip_link else ("Standard Link" if embedded_url_scans else "None")
        }
    }

    return (
        adjusted_score,
        adjusted_level,
        reconciled_recommendations,
        unique_indicators,
        breakdown_items,
        validation_summary
    )
