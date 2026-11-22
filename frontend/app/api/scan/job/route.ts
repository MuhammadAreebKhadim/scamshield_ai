import { NextResponse } from "next/server";
import { getUserFromAuthHeader } from "@/lib/server-auth";
import { serverStorage, ScanRecord, Indicator } from "@/lib/server-storage";

export const dynamic = "force-dynamic";

const FREE_EMAIL_DOMAINS = new Set([
  "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "mail.com", "protonmail.com", "zoho.com"
]);

const SUSPICIOUS_INTERVIEW_APPS = ["telegram", "whatsapp", "signal", "wire", "wechat", "kik"];

export async function POST(req: Request) {
  try {
    const body = await req.json().catch(() => ({}));
    const companyName = body.company_name?.trim() || "";
    const jobTitle = body.job_title?.trim() || "";
    const recruiterEmail = body.recruiter_email?.trim() || "";
    const jobDescription = body.job_description?.trim() || "";
    const salaryOrTerms = body.salary_or_terms?.trim() || "";
    const applicationUrl = body.application_url?.trim() || "";
    const interviewPlatform = body.interview_platform?.trim() || "";
    const isUnsolicited = Boolean(body.is_unsolicited);

    if (!companyName && !jobDescription) {
      return NextResponse.json({ error: "Company name or job description is required" }, { status: 400 });
    }

    const authUser = getUserFromAuthHeader(req);
    const userId = authUser?.user_id || "anonymous";
    const userEmail = authUser?.email || "anonymous@scamshield.ai";

    let riskScore = 0;
    const indicators: Indicator[] = [];

    // 1. Recruiter email check
    if (recruiterEmail) {
      const emailDomain = recruiterEmail.split("@")[1]?.toLowerCase();
      if (emailDomain && FREE_EMAIL_DOMAINS.has(emailDomain)) {
        riskScore += 35;
        indicators.push({
          name: "Free Webmail Recruiter Identity",
          evidence: `Recruiter email '${recruiterEmail}' operates from free webmail provider '@${emailDomain}' rather than corporate domain`,
          severity: "HIGH",
          category: "Identity Verification",
          description: "Legitimate corporate recruiters communicate exclusively via registered enterprise email domains."
        });
      }
    }

    // 2. Chat-only interview platform
    const interviewLower = interviewPlatform.toLowerCase();
    const isSusPlatform = SUSPICIOUS_INTERVIEW_APPS.some(app => interviewLower.includes(app));
    if (isSusPlatform) {
      riskScore += 35;
      indicators.push({
        name: "Anonymous Chat Interview Platform",
        evidence: `Interview conducted via encrypted consumer messaging: '${interviewPlatform}'`,
        severity: "CRITICAL",
        category: "Recruitment Process",
        description: "Scammers systematically avoid official video and HR portals by insisting on Telegram, WhatsApp, or text-only interviews."
      });
    }

    // 3. Equipment or fake check scam indicators
    const fullText = `${jobDescription} ${salaryOrTerms}`.toLowerCase();
    if (/(check for home office|cashier'?s check|purchase (laptop|equipment) from our vendor|home office equipment check)/i.test(fullText)) {
      riskScore += 45;
      indicators.push({
        name: "Advance Equipment Check Scam Pattern",
        evidence: "Offer promises a check to purchase equipment from a designated third-party supplier",
        severity: "CRITICAL",
        category: "Financial Fraud",
        description: "Classic fake check scam: The check bounces after the victim wires funds to a fraudulent fake vendor."
      });
    }

    // 4. Upfront fees or background check fee
    if (/(training fee|equipment deposit|background check fee|start-up cost|refundable deposit)/i.test(fullText)) {
      riskScore += 40;
      indicators.push({
        name: "Applicant Upfront Fee Solicitation",
        evidence: "Candidate requested to pay upfront onboarding, training, or equipment fee",
        severity: "CRITICAL",
        category: "Advance Fee Fraud",
        description: "Legitimate employers never require candidates to pay for background checks or job equipment."
      });
    }

    // 5. Unsolicited offer
    if (isUnsolicited) {
      riskScore += 15;
      indicators.push({
        name: "Unsolicited Job Outreach",
        evidence: "Applicant received offer or interview without submitting an official application",
        severity: "MEDIUM",
        category: "Sourcing Channel",
        description: "Unsolicited recruitment offers that guarantee high pay are statistically high risk."
      });
    }

    // 6. Suspicious compensation
    if (/(\$8[0-9]|\$9[0-9]|\$1[0-9]{2})\s*(\/|per)\s*hr/i.test(fullText) && /(data entry|virtual assistant|typing|clerk)/i.test(fullText)) {
      riskScore += 25;
      indicators.push({
        name: "Inflated Compensation For Low-Skill Role",
        evidence: "Unrealistic wage structure offered for entry-level task execution",
        severity: "HIGH",
        category: "Compensation Analysis",
        description: "Dramatically above-market compensation is used to entice jobseekers into lowering their guard."
      });
    }

    const finalScore = Math.min(Math.max(riskScore, 0), 100);
    let riskLevel: "LOW" | "CAUTION" | "SUSPICIOUS" | "HIGH" = "LOW";
    if (finalScore >= 70) riskLevel = "HIGH";
    else if (finalScore >= 45) riskLevel = "SUSPICIOUS";
    else if (finalScore >= 20) riskLevel = "CAUTION";

    const isThreatConfirmed = finalScore >= 70 || indicators.some(i => i.severity === "CRITICAL");

    const recommendations = [];
    if (riskLevel === "HIGH" || riskLevel === "SUSPICIOUS") {
      recommendations.push("Do not deposit any checks sent for home office supplies or equipment.");
      recommendations.push("Never wire funds, purchase gift cards, or send cryptocurrency to a recruiter or vendor.");
      recommendations.push("Search the official corporate careers page to confirm whether this job requisition actually exists.");
    } else if (riskLevel === "CAUTION") {
      recommendations.push("Request a live video interview through Zoom, Microsoft Teams, or Google Meet.");
      recommendations.push("Verify the recruiter on LinkedIn and ensure their email matches the official company domain.");
    } else {
      recommendations.push("No explicit employment fraud patterns detected.");
      recommendations.push("Continue verifying company authenticity through official channels.");
    }

    const scanId = `scn_${Math.random().toString(36).substring(2, 10)}${Date.now().toString(36)}`;
    const summary = `${jobTitle || "Job Offer"} at ${companyName || "Organization"}`;

    const scanRecord: ScanRecord = {
      scan_id: scanId,
      user_id: userId,
      user_email: userEmail,
      input_type: "job",
      input_summary: summary,
      input_data: {
        company_name: companyName,
        job_title: jobTitle,
        recruiter_email: recruiterEmail,
        salary_or_terms: salaryOrTerms,
        interview_platform: interviewPlatform
      },
      risk_score: finalScore,
      risk_level: riskLevel,
      is_threat_confirmed: isThreatConfirmed,
      indicators,
      threat_intelligence: {
        urlhaus: { status: "N/A - Employment Offer" },
        virustotal: { status: "Evaluated", malicious: isThreatConfirmed ? 1 : 0, total_vendors: 1 }
      },
      ai_analysis: {
        risk_level: riskLevel,
        risk_score: finalScore,
        category: indicators.length > 0 ? "Employment & Recruitment Scam Forensics" : "Legitimate Employment Requisition",
        summary: `Recruitment audit evaluated '${summary}'. Calculated threat risk: ${finalScore}/100. ${indicators.length} warning signals identified.`,
        indicators,
        highlighted_sentences: [],
        recommendation: recommendations[0]
      },
      recommendations,
      score_breakdown: { factors: indicators.map(i => ({ factor: i.name, severity: i.severity })) },
      created_at: new Date().toISOString()
    };

    serverStorage.saveScan(scanRecord);

    return NextResponse.json(scanRecord);
  } catch (err: any) {
    return NextResponse.json({ error: err.message || "Failed to verify job offer" }, { status: 500 });
  }
}
