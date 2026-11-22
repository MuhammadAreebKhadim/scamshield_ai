import re
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional

# 1. Explicit Sensitive Information Requests (Demanding secret tokens)
EXPLICIT_SECRET_DEMANDS = [
    r"(?:send|provide|share|enter|reply\s+with|text\s+me)\s+(?:your\s+)?(?:password|pin|atm\s*pin|cvv|cvc|otp|one-time\s*(?:passcode|password)|secret\s*code)",
    r"enter\s+(?:your\s+)?(?:password|pin|otp)",
    r"(?:cnic|ssn|social\s*security\s*number|id\s*card\s*number)\s+(?:and\s+password)",
    r"(?:seed\s*phrase|recovery\s*phrase|private\s*key)"
]

# 2. Account Credential Verification Attempts (Call-to-action to verify)
CREDENTIAL_VERIFICATION_CALLS = [
    r"verify\s+(?:your\s+)?(?:account|identity|banking\s*app|wallet|profile|details)\s*(?:immediately|now|below|at|here)?",
    r"confirm\s+(?:your\s+)?(?:account|identity|credentials|information)",
    r"(?:re-authenticate|re-verify|unlock|reactivate)\s+(?:your\s+)?(?:account|access)",
    r"click\s+(?:the\s+link\s+)?(?:below\s+)?to\s+verify",
    r"login\s+to\s+(?:confirm|verify|restore|unfreeze|keep)\s+(?:your\s+)?account"
]

# 3. Account Suspension / Coercive Threats (Fear lever)
ACCOUNT_SUSPENSION_THREATS = [
    r"account\s+will\s+be\s+(?:suspended|terminated|blocked|closed|deactivated|frozen|disabled)\s*(?:immediately|within|today)?",
    r"(?:avoid|prevent)\s+(?:account\s+)?(?:suspension|termination|closure|restriction|blocking)",
    r"unusual\s+(?:activity|sign-in|login|access)\s+detected",
    r"security\s+alert:\s*account\s+(?:flagged|locked|restricted)",
    r"immediate\s+action\s+(?:required|necessary)\s+to\s+keep\s+your\s+account\s+active"
]

# 4. Artificial Urgency & Deadlines
URGENCY_TIMELINES = [
    r"within\s+\d+\s+(?:hours?|minutes?|days?)",
    r"act\s+(?:now|immediately|fast|urgently)",
    r"limited\s+time\s+(?:remaining|only)",
    r"urgent\s+action\s+required",
    r"deadline:\s*\d+\s*(?:hours?|minutes?)",
    r"last\s+chance\s+to\s+(?:verify|avoid|claim)"
]

# 5. Generic Unverified Authority (Titles used to claim trust without named institution)
GENERIC_SECURITY_TITLES = [
    r"\bsecurity\s+department\b",
    r"\bfraud\s+(?:prevention|investigation|monitoring)\s+(?:team|department|unit)\b",
    r"\baccount\s+(?:protection|security|support)\s+team\b",
    r"\bhelp\s*desk\s+support\b",
    r"\bsystem\s+administrator\b"
]

# 6. Specific Brand / Agency Impersonation (Named banks, government or enterprise entities)
NAMED_BRAND_IMPERSONATION = [
    r"(?:hbl|ubl|meezan|mcb|bank\s*alfalah|allied\s*bank|chase|wellsfargo|bank\s*of\s*america|citi|hsbc|barclays)\s+(?:security|fraud|support|portal)",
    r"(?:fbr|irs|police|fia|customs|court|cybercrime|fbi|treasury)\s+(?:notice|investigation|warrant)",
    r"(?:microsoft|google|apple|paypal|amazon|netflix|meta|facebook)\s+security\s+team"
]

# 7. Advance Fee & Financial Demands
FINANCIAL_PAYMENT_DEMANDS = [
    r"(?:pay|send|transfer|deposit|remit)\s+(?:pkr|usd|inr|\$|rs\.?|eur|gbp)?\s*\d+[\d,]*",
    r"(?:registration|processing|clearance|security|equipment|courier|dispatch)\s+fee[s]?",
    r"(?:easypaisa|jazzcash|western\s*union|moneygram|gift\s*card)",
    r"(?:usdt|crypto|bitcoin|btc|eth|binance\s*pay|trc20)"
]

# 8. Unrealistic Hiring / Lottery Lures
UNREALISTIC_LURES = [
    r"no\s+interview\s+required",
    r"guaranteed\s+(?:selection|job|employment|income|profit)",
    r"(?:lottery|sweepstakes|jackpot|lucky\s*draw)\s+winner",
    r"you\s+have\s+won\s+\$?\d+[\d,]*"
]

# Suspicious file extensions for attachment analysis
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".iso", ".vbs", ".js", ".bat", ".cmd", ".docm", 
    ".xlsm", ".pptm", ".hta", ".wsf", ".jar", ".zip", ".rar", ".7z"
}

def extract_urls_from_text(text: str) -> List[str]:
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    urls = re.findall(url_pattern, text)
    cleaned = []
    for u in urls:
        u = u.rstrip(".,;!?:)'\"]}")
        if u.startswith("www."):
            u = "https://" + u
        cleaned.append(u)
    return list(set(cleaned))

def split_sentences(text: str) -> List[str]:
    sentences = re.split(r'(?<=[.!?\n])\s+', text)
    return [s.strip() for s in sentences if s.strip()]

def parse_email_headers_from_text(text: str) -> Dict[str, Any]:
    """
    Extracts standard email headers if present (From, Reply-To, Subject, SPF, DKIM, DMARC, Attachments).
    """
    from_match = re.search(r'(?i)^from:\s*([^\r\n]+)', text, re.MULTILINE)
    reply_to_match = re.search(r'(?i)^reply-to:\s*([^\r\n]+)', text, re.MULTILINE)
    subject_match = re.search(r'(?i)^subject:\s*([^\r\n]+)', text, re.MULTILINE)
    
    sender_email = None
    sender_domain = None
    if from_match:
        from_val = from_match.group(1).strip()
        addr_match = re.search(r'[\w\.-]+@[\w\.-]+', from_val)
        if addr_match:
            sender_email = addr_match.group(0).lower()
            sender_domain = sender_email.split("@")[1]

    reply_to_email = None
    if reply_to_match:
        reply_val = reply_to_match.group(1).strip()
        raddr_match = re.search(r'[\w\.-]+@[\w\.-]+', reply_val)
        if raddr_match:
            reply_to_email = raddr_match.group(0).lower()

    # Reply-To mismatch detection
    reply_to_mismatch = False
    if sender_email and reply_to_email and sender_email != reply_to_email:
        reply_to_mismatch = True

    # Authentication headers check
    spf_match = re.search(r'(?i)(?:received-spf|spf):\s*(pass|fail|softfail|neutral|none)', text)
    dkim_match = re.search(r'(?i)dkim=(pass|fail)', text)
    dmarc_match = re.search(r'(?i)dmarc=(pass|fail)', text)

    # Attachments detected via text / header
    attachment_matches = re.findall(r'[\w\.-]+\.(?:exe|scr|iso|vbs|js|bat|docm|xlsm|zip|rar|7z|pdf|docx)', text, re.IGNORECASE)
    suspicious_attachments = [
        att for att in attachment_matches 
        if any(att.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS)
    ]

    has_headers = bool(from_match or subject_match or spf_match)

    return {
        "has_headers": has_headers,
        "sender_email": sender_email,
        "sender_domain": sender_domain,
        "reply_to_email": reply_to_email,
        "reply_to_mismatch": reply_to_mismatch,
        "subject": subject_match.group(1).strip() if subject_match else None,
        "spf_status": spf_match.group(1).lower() if spf_match else ("Not Found in Body" if not has_headers else "Not Specified"),
        "dkim_status": dkim_match.group(1).lower() if dkim_match else ("Not Found in Body" if not has_headers else "Not Specified"),
        "dmarc_status": dmarc_match.group(1).lower() if dmarc_match else ("Not Found in Body" if not has_headers else "Not Specified"),
        "detected_attachments": list(set(attachment_matches)),
        "suspicious_attachments": list(set(suspicious_attachments)),
        "has_suspicious_attachment": len(suspicious_attachments) > 0
    }

def analyze_text_patterns(text: str) -> Dict[str, Any]:
    matched_categories: Dict[str, List[str]] = {}
    flagged_sentences: List[Dict[str, str]] = []
    sentences = split_sentences(text)

    # Header analysis
    header_info = parse_email_headers_from_text(text)

    # Detailed pattern checking
    has_explicit_secret = False
    has_cred_verification = False
    has_suspension_threat = False
    has_urgency = False
    has_generic_authority = False
    has_brand_impersonation = False
    has_payment_demand = False
    has_unrealistic_lures = False

    for sentence in sentences:
        s_lower = sentence.lower()
        matched = False
        reason = ""
        sev = "LOW"

        # 1. Explicit secret demand
        for pat in EXPLICIT_SECRET_DEMANDS:
            m = re.search(pat, s_lower)
            if m:
                has_explicit_secret = True
                matched = True
                reason = "Explicit Password / OTP / PIN Demand"
                sev = "CRITICAL"
                break

        # 2. Account credential verification call
        if not matched:
            for pat in CREDENTIAL_VERIFICATION_CALLS:
                m = re.search(pat, s_lower)
                if m:
                    has_cred_verification = True
                    matched = True
                    reason = "Account Credential Verification Attempt (Suspected Harvesting)"
                    sev = "HIGH"
                    break

        # 3. Account suspension threat
        if not matched:
            for pat in ACCOUNT_SUSPENSION_THREATS:
                m = re.search(pat, s_lower)
                if m:
                    has_suspension_threat = True
                    matched = True
                    reason = "Account Suspension Threat & Coercion"
                    sev = "HIGH"
                    break

        # 4. Urgency
        if not matched:
            for pat in URGENCY_TIMELINES:
                m = re.search(pat, s_lower)
                if m:
                    has_urgency = True
                    matched = True
                    reason = "Artificial Urgency & Deadline Coercion"
                    sev = "MEDIUM"
                    break

        # 5. Generic authority
        if not matched:
            for pat in GENERIC_SECURITY_TITLES:
                m = re.search(pat, s_lower)
                if m:
                    has_generic_authority = True
                    matched = True
                    reason = "Unverified Security Identity ('Security Department')"
                    sev = "MEDIUM"
                    break

        # 6. Specific brand impersonation
        if not matched:
            for pat in NAMED_BRAND_IMPERSONATION:
                m = re.search(pat, s_lower)
                if m:
                    has_brand_impersonation = True
                    matched = True
                    reason = "Named Brand / Agency Impersonation Attempt"
                    sev = "HIGH"
                    break

        # 7. Payment demand
        if not matched:
            for pat in FINANCIAL_PAYMENT_DEMANDS:
                m = re.search(pat, s_lower)
                if m:
                    has_payment_demand = True
                    matched = True
                    reason = "Financial Fraud / Advance Payment Demand"
                    sev = "CRITICAL"
                    break

        # 8. Unrealistic lure
        if not matched:
            for pat in UNREALISTIC_LURES:
                m = re.search(pat, s_lower)
                if m:
                    has_unrealistic_lures = True
                    matched = True
                    reason = "Deceptive Offer / Unrealistic Guarantee"
                    sev = "HIGH"
                    break

        if matched:
            flagged_sentences.append({
                "text": sentence,
                "reason": reason,
                "severity": sev
            })

    extracted_urls = extract_urls_from_text(text)

    # Social engineering profile
    social_engineering = {
        "fear_intimidation": has_suspension_threat,
        "artificial_urgency": has_urgency,
        "authority_claim": has_generic_authority or has_brand_impersonation,
        "financial_greed": has_payment_demand or has_unrealistic_lures,
        "credential_harvesting_intent": has_explicit_secret or has_cred_verification
    }

    return {
        "flagged_sentences": flagged_sentences,
        "extracted_urls": extracted_urls,
        "total_flagged": len(flagged_sentences),
        "header_analysis": header_info,
        "social_engineering": social_engineering,
        # Refined evidence states
        "has_explicit_secret_demand": has_explicit_secret,
        "has_credential_verification": has_cred_verification,
        "has_suspension_threat": has_suspension_threat,
        "has_urgency": has_urgency,
        "has_generic_authority": has_generic_authority,
        "has_brand_impersonation": has_brand_impersonation,
        "has_payment_demand": has_payment_demand,
        "has_unrealistic_lures": has_unrealistic_lures,
        "has_suspicious_attachment": header_info.get("has_suspicious_attachment", False),
        "reply_to_mismatch": header_info.get("reply_to_mismatch", False)
    }
