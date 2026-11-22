import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, Optional, List
from backend.detectors.job_detector import analyze_job_offer
from backend.detectors.career_verifier import verify_official_job_listing
from backend.ai.message_analyzer import analyze_with_ai
from backend.services.risk_engine import calculate_risk_score
from backend.services.url_service import scan_url_service
from backend.database.models import ScanRecord
from backend.database.connection import db

def scan_job_service(
    company_name: str,
    job_title: str,
    recruiter_email: str,
    job_description: str,
    salary_or_terms: str = "",
    application_url: str = "",
    recruiter_phone: str = "",
    interview_platform: str = "",
    is_unsolicited: bool = False,
    user_id: Optional[str] = None,
    user_email: Optional[str] = None
) -> ScanRecord:
    # 1. Core Rule & Pattern Detection
    job_result = analyze_job_offer(
        company_name=company_name,
        job_title=job_title,
        recruiter_email=recruiter_email,
        job_description=job_description,
        salary_or_terms=salary_or_terms,
        application_url=application_url,
        recruiter_phone=recruiter_phone,
        interview_platform=interview_platform,
        is_unsolicited=is_unsolicited
    )

    # 2. Official Careers Board Verification Check
    career_verification = verify_official_job_listing(company_name, job_title)

    full_text = (
        f"Company: {company_name}\n"
        f"Job Title: {job_title}\n"
        f"Recruiter Email: {recruiter_email}\n"
        f"Recruiter Phone/WhatsApp: {recruiter_phone}\n"
        f"Interview Platform: {interview_platform}\n"
        f"Salary/Terms: {salary_or_terms}\n"
        f"Application URL: {application_url}\n"
        f"Job Description: {job_description}\n"
        f"Unsolicited Contact: {'Yes' if is_unsolicited else 'No'}"
    )

    # 3. Parallelize AI and URL scanner
    with ThreadPoolExecutor(max_workers=3) as executor:
        ai_future = executor.submit(
            analyze_with_ai,
            full_text,
            "Job Offer Recruitment Verification",
            {
                "company": company_name,
                "email": recruiter_email,
                "is_domain_mismatch": job_result["is_domain_mismatch"],
                "payment_detected": job_result["payment_detected"]
            }
        )

        url_future = None
        if application_url:
            url_future = executor.submit(scan_url_service, application_url, user_id, user_email)

        try:
            ai_res = ai_future.result(timeout=14)
        except Exception:
            ai_res = {
                "risk_score": 10,
                "risk_level": "LOW",
                "indicators": [],
                "highlighted_sentences": [],
                "recommendation": "Verify recruiter details directly on the official careers page."
            }

        url_scan = None
        if url_future:
            try:
                url_scan = url_future.result(timeout=10)
            except Exception:
                pass

    # 4. Extract rich telemetry for application URL
    application_url_analysis = None
    threat_intel = {}
    if url_scan and isinstance(url_scan, ScanRecord):
        threat_intel = url_scan.threat_intelligence or {}
        u_input_data = url_scan.input_data or {}
        ip_check = u_input_data.get("ip_check", {})
        brand_check = u_input_data.get("brand_check", {})
        dns_records = u_input_data.get("dns_records", {})
        domain_age = u_input_data.get("domain_age", {})

        application_url_analysis = {
            "url": application_url,
            "risk_score": url_scan.risk_score,
            "risk_level": url_scan.risk_level,
            "domain_age": domain_age.get("message", "Unavailable — Registration data not retrieved."),
            "domain_age_days": domain_age.get("age_days"),
            "brand_similarity": f"{brand_check.get('similarity_percentage', 0)}% ({brand_check.get('reason', 'No typosquatting')})",
            "dns_status": dns_records.get("dns_status", "Resolved"),
            "ip_classification": ip_check.get("ip_classification", "Domain Host"),
            "virustotal": f"{threat_intel.get('virustotal', {}).get('malicious', 0)}/{threat_intel.get('virustotal', {}).get('total_vendors', 60) or 60} Flagged",
            "google_safe_browsing": "Threat Found" if threat_intel.get("google_safe_browsing", {}).get("is_threat_found") else "No Match",
            "urlhaus": "Malware Found" if threat_intel.get("urlhaus", {}).get("is_malicious") else "No Match",
            "findings": [ind.get("name") for ind in url_scan.indicators[:3]]
        }

    # 5. Build Grouped Indicators (Combining duplicates cleanly)
    indicators: List[Dict[str, Any]] = []

    # Group 1: Recruiter Identity Mismatch (Combined group)
    if job_result["is_domain_mismatch"]:
        indicators.append({
            "name": "Recruiter Identity Mismatch",
            "evidence": job_result["identity_warning"],
            "severity": "CRITICAL" if job_result["is_free_webmail"] else "HIGH",
            "category": "Identity Verification",
            "sub_signals": [
                "Free public webmail (@gmail.com) used for enterprise recruitment" if job_result["is_free_webmail"] else "Domain mismatch with official employer",
                f"Official domains expected: {', '.join(job_result['expected_domains']) if job_result['expected_domains'] else 'Corporate email domain'}"
            ]
        })
    elif job_result["is_verified_corporate"]:
        indicators.append({
            "name": "Verified Corporate Email Domain",
            "evidence": job_result["identity_warning"],
            "severity": "SAFE",
            "category": "Identity Verification"
        })

    # Group 2: Advance Fee Recruitment Fraud (Combined group)
    if job_result["payment_detected"]:
        indicators.append({
            "name": "Advance Fee Recruitment Fraud",
            "evidence": f"Candidate payment demand detected: {', '.join(job_result['payment_evidence'])}",
            "severity": "CRITICAL",
            "category": "Recruitment Fraud",
            "sub_signals": [
                "Upfront registration, training, or equipment fee solicited",
                "Legitimate enterprise employers never charge candidates advance fees"
            ]
        })

    # Group 3: Application Portal Telemetry
    if application_url_analysis:
        if application_url_analysis.get("risk_score", 0) >= 35 or url_scan.is_threat_confirmed:
            indicators.append({
                "name": "Suspicious Application Portal",
                "evidence": f"Application portal '{application_url}' scored {application_url_analysis['risk_score']}/100 ({application_url_analysis['risk_level']}). Host: {application_url_analysis['ip_classification']}.",
                "severity": "HIGH",
                "category": "Application Portal"
            })

    # Group 4: Supporting Evidence (Clearly labeled as supporting, not proof of fraud)
    if job_result["has_salary_anomaly"]:
        indicators.append({
            "name": "Unusually High Compensation Claim",
            "evidence": job_result["salary_anomaly_detail"],
            "severity": "MEDIUM",
            "category": "Supporting Evidence"
        })

    if job_result["no_interview_detected"]:
        indicators.append({
            "name": "Simplified Recruitment / No Interview Stated",
            "evidence": f"Unrealistic hiring conditions: {', '.join(job_result['no_interview_evidence'])} (Treated as supporting anomaly).",
            "severity": "MEDIUM",
            "category": "Supporting Evidence"
        })

    if job_result["suspicious_interview"]:
        indicators.append({
            "name": "Informal Chat-Only Interview Channel",
            "evidence": f"Interview scheduled exclusively on messaging apps: {', '.join(job_result['interview_evidence'])} (Supporting indicator).",
            "severity": "MEDIUM",
            "category": "Supporting Evidence"
        })

    # AI contextual indicators (deduplicated against primary evidence groups)
    existing_concepts = {"domain", "email", "webmail", "sender", "payment", "fee", "interview", "salary", "application", "portal", "appointment"}
    for ind in ai_res.get("indicators", []):
        name = ind.get("name", "AI Recruitment Indicator")
        name_lower = name.lower()
        if any(c in name_lower for c in existing_concepts):
            continue
        indicators.append({
            "name": name,
            "evidence": ind.get("evidence", ""),
            "severity": ind.get("severity", "MEDIUM"),
            "category": "AI Contextual Analysis"
        })

    # 6. Signal Weights & Scoring
    signals: Dict[str, Any] = {
        "payment_request": job_result["payment_detected"],
        "unofficial_sender": job_result["is_domain_mismatch"],
        "fake_recruitment": job_result["no_interview_detected"] or job_result["suspicious_interview"],
        "ai_score": ai_res.get("risk_score", 0),
        "urlhaus_match": False,
        "google_match": False,
        "virustotal_malicious_count": 0
    }

    if url_scan:
        signals["virustotal_malicious_count"] = threat_intel.get("virustotal", {}).get("malicious", 0)
        signals["google_match"] = threat_intel.get("google_safe_browsing", {}).get("is_threat_found", False)
        signals["urlhaus_match"] = threat_intel.get("urlhaus", {}).get("is_malicious", False)

    raw_score, raw_level, is_threat_confirmed, breakdown = calculate_risk_score(signals)
    breakdown_items = breakdown.get("calculation_items", [])

    # Consistency Validation Floor for Fake Jobs
    # Advance Payment Demand + Recruiter Mismatch = Definitive Fake Recruitment (85-90 HIGH RISK)
    final_score = raw_score
    if job_result["payment_detected"] and job_result["is_domain_mismatch"]:
        final_score = max(final_score, 85)
        diff = final_score - raw_score
        if diff > 0:
            breakdown_items.append({
                "factor": "Advance Fee Recruitment Trap Alignment",
                "points": diff,
                "description": "Critical risk escalation: Unsolicited advance fee demand combined with free webmail recruiter mismatch."
            })
    elif job_result["payment_detected"]:
        final_score = max(final_score, 80)
    elif job_result["is_free_webmail"] and (job_result["no_interview_detected"] or job_result["suspicious_interview"]):
        final_score = max(final_score, 75)

    final_score = min(max(final_score, 0), 100)
    if final_score >= 70:
        final_level = "HIGH"
    elif final_score >= 40:
        final_level = "SUSPICIOUS"
    elif final_score >= 20:
        final_level = "CAUTION"
    else:
        final_level = "LOW"

    # 7. Actionable Recommendations
    recommendations = []
    if final_score >= 70:
        recommendations.append("NEVER send advance money, registration fees, or equipment payments for any job offer.")
        if career_verification.get("portal_url"):
            recommendations.append(f"Verify active requisitions directly on the official {career_verification['portal_name']} ({career_verification['portal_url']}).")
        recommendations.append("Legitimate corporate recruiters never hire candidates through free consumer webmail (@gmail.com) without formal multi-stage screening.")
    elif final_score >= 40:
        recommendations.append("Request an official video interview conducted via enterprise calendar scheduling.")
        recommendations.append("Do not disclose government IDs (CNIC/SSN) or banking details over messaging apps.")
    else:
        recommendations.append("Standard hiring flow: verify recruiter corporate identity on LinkedIn and official careers portal before interview.")

    scan_id = f"SC-{uuid.uuid4().hex[:6].upper()}"

    reconciled_breakdown = {
        "final_score": final_score,
        "risk_level": final_level,
        "is_threat_confirmed": is_threat_confirmed or final_score >= 70,
        "calculation_items": breakdown_items,
        "formula": f"Sum of {len(breakdown_items)} validated risk indicators = {final_score}/100"
    }

    scan_record = ScanRecord(
        scan_id=scan_id,
        user_id=user_id or "anonymous",
        user_email=user_email or "anonymous@scamshield.ai",
        input_type="job",
        input_summary=f"{company_name or 'Recruiter'} - {job_title or 'Position'}",
        input_data={
            "company_name": company_name,
            "job_title": job_title,
            "recruiter_email": recruiter_email,
            "recruiter_phone": recruiter_phone,
            "interview_platform": interview_platform,
            "salary_or_terms": salary_or_terms,
            "application_url": application_url,
            "is_unsolicited": is_unsolicited,
            "job_description_preview": job_description[:200],
            "domain_verification": job_result,
            "career_verification": career_verification,
            "application_url_analysis": application_url_analysis
        },
        risk_score=final_score,
        risk_level=final_level,
        is_threat_confirmed=is_threat_confirmed or final_score >= 70,
        indicators=indicators,
        threat_intelligence=threat_intel,
        ai_analysis=ai_res,
        recommendations=recommendations,
        score_breakdown=reconciled_breakdown
    )

    return db.save_scan(scan_record)
