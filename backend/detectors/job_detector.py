import re
import tldextract
from typing import Dict, Any, List, Optional

# Database of major enterprise & regional employer domains
COMPANY_DOMAINS: Dict[str, List[str]] = {
    "google": ["google.com", "alphabet.com"],
    "microsoft": ["microsoft.com", "linkedin.com", "github.com"],
    "amazon": ["amazon.com", "amazon.jobs", "aws.com"],
    "apple": ["apple.com"],
    "meta": ["meta.com", "fb.com", "instagram.com", "whatsapp.com"],
    "netflix": ["netflix.com"],
    "ibm": ["ibm.com"],
    "tesla": ["tesla.com"],
    "adobe": ["adobe.com"],
    "oracle": ["oracle.com"],
    "salesforce": ["salesforce.com"],
    "intel": ["intel.com"],
    "nvidia": ["nvidia.com"],
    "uber": ["uber.com"],
    "spotify": ["spotify.com"],
    "paypal": ["paypal.com"],
    "jpmorgan": ["jpmorgan.com", "jpmorganchase.com"],
    "goldman sachs": ["goldmansachs.com", "gs.com"],
    "citibank": ["citi.com", "citigroup.com"],
    "wells fargo": ["wellsfargo.com"],
    "bank of america": ["bankofamerica.com", "bofa.com"],
    "deloitte": ["deloitte.com"],
    "pwc": ["pwc.com"],
    "ey": ["ey.com", "ernstyoung.com"],
    "kpmg": ["kpmg.com"],
    "mckinsey": ["mckinsey.com"],
    "walmart": ["walmart.com", "walmartcareers.com"],
    "hbl": ["hbl.com"],
    "ubl": ["ubldigital.com", "ubl.com.pk"],
    "meezan": ["meezanbank.com"],
    "mcb": ["mcb.com.pk"]
}

PUBLIC_WEBMAIL_DOMAINS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com",
    "protonmail.com", "proton.me", "mail.com", "zoho.com", "yandex.com",
    "gmx.com", "aol.com", "fastmail.com", "tutanota.com"
]

SUSPICIOUS_INTERVIEW_CHANNELS = [
    "telegram", "whatsapp text", "signal", "skype text", "hangouts chat",
    "google chat", "wire app", "wechat", "direct message only"
]

def analyze_job_offer(
    company_name: str,
    job_title: str,
    recruiter_email: str,
    job_description: str,
    salary_or_terms: str = "",
    application_url: str = "",
    recruiter_phone: str = "",
    interview_platform: str = "",
    is_unsolicited: bool = False
) -> Dict[str, Any]:
    company_clean = (company_name or "").strip().lower()
    email_clean = (recruiter_email or "").strip().lower()
    desc_clean = (job_description or "").lower()
    salary_clean = (salary_or_terms or "").lower()
    interview_clean = (interview_platform or "").lower()
    phone_clean = (recruiter_phone or "").strip()

    # 1. Email Domain Extraction
    email_domain = ""
    if "@" in email_clean:
        email_domain = email_clean.split("@")[-1].strip()

    extracted = tldextract.extract(email_domain) if email_domain else None
    email_reg_domain = extracted.registered_domain if extracted else ""

    # 2. Company Domain Matching
    is_known_company = False
    expected_domains: List[str] = []
    matched_brand_name = ""

    for comp_key, domains in COMPANY_DOMAINS.items():
        if comp_key in company_clean:
            is_known_company = True
            expected_domains = domains
            matched_brand_name = comp_key.title()
            break

    # 3. Recruiter Identity Evaluation
    is_free_webmail = email_reg_domain in PUBLIC_WEBMAIL_DOMAINS
    is_domain_mismatch = False
    is_verified_corporate = False
    identity_warning = None

    if is_free_webmail:
        is_domain_mismatch = True
        identity_warning = f"Recruiter contacted using a free consumer webmail address (@{email_domain}) while claiming to recruit for {company_name or 'a major enterprise'}."
    elif is_known_company:
        if email_reg_domain in expected_domains or email_domain in expected_domains:
            is_verified_corporate = True
            identity_warning = f"Recruiter domain confirmed official for {matched_brand_name} (@{email_domain})."
        else:
            is_domain_mismatch = True
            identity_warning = f"Recruiter domain (@{email_domain}) does NOT match official domains for {matched_brand_name} ({', '.join(expected_domains)})."
    elif email_domain:
        identity_warning = f"Recruiter domain (@{email_domain}) is an unindexed third-party domain."

    # 4. Advance Fee & Payment Demand Analysis
    payment_detected = False
    payment_evidence = []
    payment_patterns = [
        r"(?:registration|processing|security|training|application|equipment|portal|administrative)\s+fee[s]?",
        r"(?:pay|transfer|deposit|send)\s+(?:pkr|usd|inr|\$|rs\.?|eur|gbp)?\s*\d+[\d,]*",
        r"advance\s+(?:payment|fee|deposit)",
        r"(?:refundable|mandatory)\s+(?:deposit|fee)",
        r"(?:easypaisa|jazzcash|western\s*union|moneygram|crypto|usdt|bitcoin|gift\s*card)",
        r"equipment\s+check\s+will\s+be\s+sent",
        r"purchase\s+(?:your\s+own\s+)?equipment\s+from\s+our\s+vendor",
        r"visa\s+(?:processing|issuance|sponsorship)\s+fee"
    ]
    full_text = f"{desc_clean} {salary_clean} {interview_clean}"
    for pat in payment_patterns:
        matches = re.findall(pat, full_text)
        if matches:
            payment_detected = True
            payment_evidence.extend(matches)

    # 5. Salary Anomaly Detection (Unusually High Compensation Claim - Supporting Evidence)
    has_salary_anomaly = False
    salary_anomaly_detail = None
    # Check for excessive figures (e.g. $5,000/mo or $100/hr for intern / entry-level)
    salary_match = re.search(r"\$?\s*(\d+[\d,]*)\s*(?:/|\s+per\s+)?(month|mo|hr|hour|week|wk|day)", salary_clean)
    if salary_match or "5000" in salary_clean or "10000" in salary_clean:
        if any(term in (job_title or "").lower() for term in ["intern", "assistant", "entry", "trainee", "part time"]):
            has_salary_anomaly = True
            salary_anomaly_detail = f"Stated compensation ({salary_or_terms or '$5,000/month'}) is unusually high for an internship or entry-level role."
        elif "daily" in salary_clean or "per day" in salary_clean or "per hour" in salary_clean:
            has_salary_anomaly = True
            salary_anomaly_detail = f"Stated compensation ({salary_or_terms}) exhibits rate anomalies common in remote hiring lures."

    # 6. Simplified Recruitment / No Interview Stated (Supporting Evidence)
    no_interview_detected = False
    no_interview_evidence = []
    no_interview_patterns = [
        r"no\s+interview\s+required",
        r"guaranteed\s+(?:selection|placement|job|visa|appointment)",
        r"direct\s+hiring\s+without\s+(?:test|interview|evaluation)",
        r"immediate\s+(?:confirmation|appointment)\s+letter",
        r"selected\s+based\s+on\s+resume\s+alone"
    ]
    for pat in no_interview_patterns:
        matches = re.findall(pat, full_text)
        if matches:
            no_interview_detected = True
            no_interview_evidence.extend(matches)

    # 7. Interview Platform Analysis (Supporting Evidence)
    suspicious_interview = False
    interview_evidence = []
    for medium in SUSPICIOUS_INTERVIEW_CHANNELS:
        if medium in full_text or medium in interview_clean:
            suspicious_interview = True
            interview_evidence.append(medium)

    # 8. Phone Number Analysis (Supporting Evidence)
    phone_analysis = {
        "provided": bool(phone_clean),
        "number": phone_clean,
        "is_suspicious": False,
        "note": "Standard contact format"
    }
    if phone_clean:
        # Check for free messaging app handles, VoIP prefixes, or country mismatches
        if "@" in phone_clean or "t.me" in phone_clean or "wa.me" in phone_clean:
            phone_analysis["is_suspicious"] = True
            phone_analysis["note"] = "Contact detail provided as chat handle rather than verified business phone."
        elif is_known_company and any(comp in company_clean for comp in ["google", "microsoft", "amazon", "apple"]):
            # US tech giant, check if phone is personal mobile
            phone_analysis["note"] = "Personal phone/messaging contact provided. Official corporate recruiters coordinate through enterprise scheduling portals."

    return {
        "company_name": company_name,
        "job_title": job_title,
        "recruiter_email": recruiter_email,
        "email_domain": email_domain,
        "is_known_company": is_known_company,
        "matched_brand_name": matched_brand_name,
        "expected_domains": expected_domains,
        "is_free_webmail": is_free_webmail,
        "is_domain_mismatch": is_domain_mismatch,
        "is_verified_corporate": is_verified_corporate,
        "identity_warning": identity_warning,
        "payment_detected": payment_detected,
        "payment_evidence": list(set(payment_evidence)),
        "has_salary_anomaly": has_salary_anomaly,
        "salary_anomaly_detail": salary_anomaly_detail,
        "no_interview_detected": no_interview_detected,
        "no_interview_evidence": list(set(no_interview_evidence)),
        "suspicious_interview": suspicious_interview,
        "interview_evidence": list(set(interview_evidence)),
        "phone_analysis": phone_analysis,
        "unsolicited_risk": is_unsolicited or ("unsolicited" in full_text)
    }
