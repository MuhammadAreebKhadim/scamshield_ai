import requests
import json

payload = {
    "company_name": "Google",
    "job_title": "Software Engineer Intern",
    "recruiter_email": "recruiter@gmail.com",
    "salary_or_terms": "$5,000/month",
    "job_description": "Immediate appointment, no interview required. Please pay a PKR 2,500 registration fee.",
    "application_url": "https://google-intern-portal.fake.com",
    "interview_platform": "Telegram / Text Messaging Chat",
    "is_unsolicited": True
}

res = requests.post("http://127.0.0.1:8000/api/scan/job", json=payload)
data = res.json()

print("STATUS CODE:", res.status_code)
print("FINAL RISK SCORE:", data.get("risk_score"))
print("RISK LEVEL:", data.get("risk_level"))
print("IS THREAT CONFIRMED:", data.get("is_threat_confirmed"))
print("INDICATORS:")
for i, ind in enumerate(data.get("indicators", [])):
    print(f"  {i+1}. [{ind.get('category')}] {ind.get('name')} ({ind.get('severity')})")
    for s in ind.get("sub_signals", []):
        print(f"      - {s}")

print("\nCAREER VERIFICATION:")
cv = data.get("input_data", {}).get("career_verification", {})
print("  Status:", cv.get("status"))
print("  Portal Name:", cv.get("portal_name"))
print("  Portal URL:", cv.get("portal_url"))
print("  Search URL:", cv.get("direct_search_url"))
print("  Fee Policy:", cv.get("fee_policy"))

print("\nAPPLICATION URL ANALYSIS:")
au = data.get("input_data", {}).get("application_url_analysis", {})
print("  URL:", au.get("url"))
print("  Risk:", au.get("risk_score"), au.get("risk_level"))
print("  Domain Age:", au.get("domain_age"))
print("  Brand Match:", au.get("brand_similarity"))
print("  DNS Status:", au.get("dns_status"))
print("  Host Type:", au.get("ip_classification"))
print("  VirusTotal:", au.get("virustotal"))

print("\nSCORE BREAKDOWN CALCULATION AUDIT:")
sb = data.get("score_breakdown", {})
for item in sb.get("calculation_items", []):
    print(f"  - {item.get('factor')}: +{item.get('points')} pts | {item.get('description')}")

print("\nRECOMMENDATIONS:")
for r in data.get("recommendations", []):
    print("  *", r)
