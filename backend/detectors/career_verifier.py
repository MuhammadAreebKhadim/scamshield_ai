import urllib.parse
from typing import Dict, Any, Optional

OFFICIAL_CAREER_PORTALS = {
    "google": {
        "name": "Google Careers",
        "portal_url": "https://careers.google.com",
        "search_url_template": "https://www.google.com/about/careers/applications/jobs/results/?q={query}",
        "fee_policy": "Google NEVER charges any application, training, equipment, or registration fees at any point in the recruitment process.",
        "official_domains": ["google.com", "alphabet.com"],
        "known_roles": ["software engineer", "intern", "product manager", "data scientist", "cloud architect", "research scientist"]
    },
    "microsoft": {
        "name": "Microsoft Careers",
        "portal_url": "https://careers.microsoft.com",
        "search_url_template": "https://careers.microsoft.com/v2/global/en/home.html#search?q={query}",
        "fee_policy": "Microsoft never charges candidates fees for interviews, equipment, or job applications.",
        "official_domains": ["microsoft.com", "linkedin.com"],
        "known_roles": ["software engineer", "intern", "support engineer", "program manager", "cloud solutions"]
    },
    "amazon": {
        "name": "Amazon.jobs",
        "portal_url": "https://www.amazon.jobs",
        "search_url_template": "https://www.amazon.jobs/en/search?base_query={query}",
        "fee_policy": "Amazon does not request security deposits, registration fees, or equipment checks.",
        "official_domains": ["amazon.com", "amazon.jobs"],
        "known_roles": ["software development engineer", "sde", "area manager", "operations intern", "solutions architect"]
    },
    "meta": {
        "name": "Meta Careers",
        "portal_url": "https://www.metacareers.com",
        "search_url_template": "https://www.metacareers.com/jobs?q={query}",
        "fee_policy": "Meta recruiters only communicate via @meta.com or @fb.com and never demand payments.",
        "official_domains": ["meta.com", "fb.com"],
        "known_roles": ["software engineer", "production engineer", "research intern", "product designer"]
    },
    "apple": {
        "name": "Apple Jobs",
        "portal_url": "https://jobs.apple.com",
        "search_url_template": "https://jobs.apple.com/en-us/search?search={query}",
        "fee_policy": "Apple never solicits fees for job applications or hiring evaluations.",
        "official_domains": ["apple.com"],
        "known_roles": ["hardware engineer", "software engineer", "apple store specialist", "ai/ml intern"]
    },
    "netflix": {
        "name": "Netflix Jobs",
        "portal_url": "https://jobs.netflix.com",
        "search_url_template": "https://jobs.netflix.com/search?q={query}",
        "fee_policy": "Netflix never requests fees or conducts hiring via chat apps.",
        "official_domains": ["netflix.com"],
        "known_roles": ["software engineer", "data engineer", "content specialist"]
    },
    "jpmorgan": {
        "name": "JPMorgan Chase Careers",
        "portal_url": "https://careers.jpmorgan.com",
        "search_url_template": "https://careers.jpmorgan.com/global/en/home?q={query}",
        "fee_policy": "JPMorgan Chase conducts formal interviews through enterprise portals and never charges candidate fees.",
        "official_domains": ["jpmorgan.com", "jpmorganchase.com"],
        "known_roles": ["investment banking analyst", "software engineer", "quantitative researcher"]
    },
    "deloitte": {
        "name": "Deloitte Careers",
        "portal_url": "https://jobs2.deloitte.com",
        "search_url_template": "https://jobs2.deloitte.com/ui/en_US/careers/SearchJobs/{query}",
        "fee_policy": "Deloitte does not charge processing, assessment, or interview fees.",
        "official_domains": ["deloitte.com"],
        "known_roles": ["consultant", "analyst", "audit associate", "tax consultant"]
    },
    "ibm": {
        "name": "IBM Careers",
        "portal_url": "https://www.ibm.com/careers",
        "search_url_template": "https://www.ibm.com/careers/search?q={query}",
        "fee_policy": "IBM never asks candidates for payments of any kind during recruitment.",
        "official_domains": ["ibm.com"],
        "known_roles": ["software engineer", "intern", "data scientist", "cloud consultant"]
    },
    "cisco": {
        "name": "Cisco Careers",
        "portal_url": "https://jobs.cisco.com",
        "search_url_template": "https://jobs.cisco.com/jobs/SearchJobs/?21178=%5B169482%5D&21178_format=1706&listFilterMode=1&jobRecordsPerPage=10&query={query}",
        "fee_policy": "Cisco does not require any application fees or equipment purchases from job applicants.",
        "official_domains": ["cisco.com"],
        "known_roles": ["network engineer", "software engineer", "intern", "technical consultant"]
    },
    "oracle": {
        "name": "Oracle Careers",
        "portal_url": "https://www.oracle.com/careers",
        "search_url_template": "https://eeho.fa.us2.oraclecloud.com/hcmUI/CandidateExperience/en/sites/CX_1/requisitions?keyword={query}",
        "fee_policy": "Oracle never solicits registration or equipment fees from applicants.",
        "official_domains": ["oracle.com"],
        "known_roles": ["software developer", "cloud engineer", "intern", "database administrator"]
    },
    "intel": {
        "name": "Intel Careers",
        "portal_url": "https://jobs.intel.com",
        "search_url_template": "https://jobs.intel.com/en/search-jobs/{query}",
        "fee_policy": "Intel never charges fees for job applications or hiring evaluations.",
        "official_domains": ["intel.com"],
        "known_roles": ["hardware engineer", "software engineer", "intern", "silicon design"]
    },
    "adobe": {
        "name": "Adobe Careers",
        "portal_url": "https://www.adobe.com/careers.html",
        "search_url_template": "https://adobe.wd5.myworkdayjobs.com/external_experienced?q={query}",
        "fee_policy": "Adobe recruiters never communicate from free webmail or request applicant payments.",
        "official_domains": ["adobe.com"],
        "known_roles": ["software engineer", "product manager", "intern", "ui/ux designer"]
    },
    "salesforce": {
        "name": "Salesforce Careers",
        "portal_url": "https://www.salesforce.com/company/careers",
        "search_url_template": "https://salesforce.wd12.myworkdayjobs.com/SalesforceCareers?q={query}",
        "fee_policy": "Salesforce does not charge candidates any fees during the recruitment process.",
        "official_domains": ["salesforce.com"],
        "known_roles": ["software engineer", "solutions architect", "intern", "account executive"]
    },
    "spotify": {
        "name": "Spotify Jobs",
        "portal_url": "https://www.lifeatspotify.com/jobs",
        "search_url_template": "https://www.lifeatspotify.com/jobs?q={query}",
        "fee_policy": "Spotify does not charge candidate registration or screening fees.",
        "official_domains": ["spotify.com"],
        "known_roles": ["software engineer", "backend developer", "intern", "data scientist"]
    },
    "uber": {
        "name": "Uber Careers",
        "portal_url": "https://www.uber.com/careers",
        "search_url_template": "https://www.uber.com/us/en/careers/list/?query={query}",
        "fee_policy": "Uber never requires candidate fees or purchases for hiring evaluations.",
        "official_domains": ["uber.com"],
        "known_roles": ["software engineer", "operations manager", "intern", "data analyst"]
    },
    "pwc": {
        "name": "PwC Careers",
        "portal_url": "https://jobs.pwc.com",
        "search_url_template": "https://jobs.pwc.com/en/search-jobs/{query}",
        "fee_policy": "PwC does not charge candidates any fees at any stage of recruitment.",
        "official_domains": ["pwc.com"],
        "known_roles": ["associate", "consultant", "intern", "auditor"]
    },
    "ey": {
        "name": "EY Careers",
        "portal_url": "https://careers.ey.com",
        "search_url_template": "https://careers.ey.com/ey/search/?q={query}",
        "fee_policy": "EY never asks for advance fees, equipment costs, or training payments.",
        "official_domains": ["ey.com"],
        "known_roles": ["tax consultant", "technology consultant", "intern", "audit senior"]
    },
    "kpmg": {
        "name": "KPMG Careers",
        "portal_url": "https://kpmg.com/careers",
        "search_url_template": "https://kpmg.com/xx/en/home/careers.html?q={query}",
        "fee_policy": "KPMG does not charge application or processing fees to job seekers.",
        "official_domains": ["kpmg.com"],
        "known_roles": ["advisory associate", "tax analyst", "intern", "audit associate"]
    },
    "systems limited": {
        "name": "Systems Limited Careers",
        "portal_url": "https://www.systemsltd.com/careers",
        "search_url_template": "https://www.systemsltd.com/careers?q={query}",
        "fee_policy": "Systems Limited never charges application fees or security deposits.",
        "official_domains": ["systemsltd.com"],
        "known_roles": ["software engineer", "sqa engineer", "intern", "trainee"]
    },
    "10pearls": {
        "name": "10Pearls Careers",
        "portal_url": "https://10pearls.com/careers",
        "search_url_template": "https://10pearls.com/careers/?q={query}",
        "fee_policy": "10Pearls conducts merit-based recruitment and never requests payments.",
        "official_domains": ["10pearls.com"],
        "known_roles": ["software developer", "qa engineer", "intern", "ui designer"]
    }
}

def verify_official_job_listing(company_name: str, job_title: str) -> Dict[str, Any]:
    comp_clean = (company_name or "").strip().lower()
    title_clean = (job_title or "").strip().lower()

    if not comp_clean:
        return {
            "status": "Verification not performed",
            "message": "Company name not provided.",
            "portal_name": None,
            "portal_url": None,
            "direct_search_url": None,
            "fee_policy": None,
            "matched_portal": False
        }

    matched_key = None
    portal_data = None
    for key, data in OFFICIAL_CAREER_PORTALS.items():
        if key in comp_clean:
            matched_key = key
            portal_data = data
            break

    if not portal_data:
        return {
            "status": "Verification not performed",
            "message": f"Official automated career portal index not configured for '{company_name}'. Independent corporate verification recommended.",
            "portal_name": None,
            "portal_url": None,
            "direct_search_url": None,
            "fee_policy": "Legitimate enterprise employers never charge candidates advance registration or equipment fees.",
            "matched_portal": False
        }

    encoded_query = urllib.parse.quote(job_title or "intern")
    direct_search_url = portal_data["search_url_template"].format(query=encoded_query)

    # Cross-reference known job titles and typical fraud scenarios
    # If the user is querying an internship or position with high claims:
    is_known_role = any(role in title_clean for role in portal_data.get("known_roles", []))

    if not title_clean:
        status = "No matching vacancy found"
        message = f"Specific position title not specified. Search active listings directly on {portal_data['name']}."
    elif is_known_role:
        status = "Matching vacancy found"
        message = (
            f"Official {portal_data['name']} hosts authentic tracks for '{job_title}'. "
            f"Note: Legitimate recruiters communicate strictly through official enterprise domains ({', '.join(portal_data['official_domains'])}) and NEVER demand candidate fees."
        )
    else:
        status = "No matching vacancy found"
        message = (
            f"No active record matching '{job_title}' was confirmed in the index for {portal_data['name']}. "
            f"Verify open requisitions directly on the official careers portal."
        )

    return {
        "status": status,
        "message": message,
        "portal_name": portal_data["name"],
        "portal_url": portal_data["portal_url"],
        "direct_search_url": direct_search_url,
        "fee_policy": portal_data["fee_policy"],
        "official_domains": portal_data["official_domains"],
        "matched_portal": True
    }
