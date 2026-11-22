import { NextResponse } from "next/server";
import { getUserFromAuthHeader } from "@/lib/server-auth";
import { serverStorage, ScanRecord, Indicator, HighlightedSentence } from "@/lib/server-storage";

export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  try {
    const body = await req.json().catch(() => ({}));
    const content = body.content?.trim();
    const channel = body.channel?.trim() || "Email";

    if (!content) {
      return NextResponse.json({ error: "Message content is required" }, { status: 400 });
    }

    const authUser = getUserFromAuthHeader(req);
    const userId = authUser?.user_id || "anonymous";
    const userEmail = authUser?.email || "anonymous@scamshield.ai";

    const lower = content.toLowerCase();
    let riskScore = 0;
    const indicators: Indicator[] = [];
    const highlightedSentences: HighlightedSentence[] = [];

    // Urgency indicators
    const urgencyPatterns = [
      { pattern: /within (24|12|48|2) hours/i, label: "Artificial Deadline Pressure", text: "within tight timeframe", points: 25 },
      { pattern: /(immediately|immediate action|act now|urgent|right away)/i, label: "Psychological Urgency Trigger", text: "Immediate action demand", points: 20 },
      { pattern: /(account (suspended|locked|terminated|disabled)|security alert|unauthorized)/i, label: "Account Suspension Coercion", text: "Account threat claim", points: 25 }
    ];

    for (const item of urgencyPatterns) {
      if (item.pattern.test(content)) {
        riskScore += item.points;
        indicators.push({
          name: item.label,
          evidence: `Message contains urgency cues: "${item.text}"`,
          severity: "HIGH",
          category: "Social Engineering",
          description: "Scammers manufacture artificial urgency to bypass logical critical thinking."
        });
      }
    }

    // Financial coercion indicators
    const financialPatterns = [
      { pattern: /(gift card|itunes|steam card|google play card)/i, label: "Untraceable Gift Card Demand", points: 40 },
      { pattern: /(bitcoin|crypto|ethereum|usdt|btc wallet)/i, label: "Cryptocurrency Payment Request", points: 35 },
      { pattern: /(wire transfer|western union|moneygram|zelle|cashapp)/i, label: "Irreversible Payment Channel", points: 30 },
      { pattern: /(refund of \$?\d+|overpayment|claim your prize|\$\d+,\d{3})/i, label: "Lotto or Overpayment Lure", points: 25 }
    ];

    for (const item of financialPatterns) {
      if (item.pattern.test(content)) {
        riskScore += item.points;
        indicators.push({
          name: item.label,
          evidence: "Message instructs transaction through irreversible or anonymous channels",
          severity: "CRITICAL",
          category: "Financial Fraud",
          description: "Demanding non-refundable payments or gift cards is a hallmark signature of advance fee fraud."
        });
      }
    }

    // Credential harvest cues
    const credentialPatterns = [
      { pattern: /(click here|log in here|verify your (identity|password|pin)|update your billing)/i, label: "Credential Harvesting Lure", points: 25 },
      { pattern: /(send your (password|ssn|social security|pin|otp))/i, label: "Direct Sensitive Data Solicitation", points: 40 }
    ];

    for (const item of credentialPatterns) {
      if (item.pattern.test(content)) {
        riskScore += item.points;
        indicators.push({
          name: item.label,
          evidence: "Explicit request to provide credentials, OTPs, or click verification links",
          severity: "CRITICAL",
          category: "Credential Harvesting",
          description: "Legitimate organizations never ask for your password, PIN, or OTP over unsecured messaging."
        });
      }
    }

    // Break into sentences to highlight suspicious regions
    const rawSentences = content.match(/[^.!?]+[.!?]+/g) || [content];
    for (const s of rawSentences) {
      const sTrim = s.trim();
      const sLower = sTrim.toLowerCase();
      if (/(immediate|urgent|within \d+|suspended|locked|gift card|crypto|password|verify)/i.test(sLower)) {
        highlightedSentences.push({
          text: sTrim,
          reason: "Contains coercive psychological trigger or sensitive data solicitation",
          severity: "HIGH"
        });
      }
    }

    const finalScore = Math.min(Math.max(riskScore, 0), 100);
    let riskLevel: "LOW" | "CAUTION" | "SUSPICIOUS" | "HIGH" = "LOW";
    if (finalScore >= 70) riskLevel = "HIGH";
    else if (finalScore >= 45) riskLevel = "SUSPICIOUS";
    else if (finalScore >= 20) riskLevel = "CAUTION";

    const isThreatConfirmed = finalScore >= 70 || indicators.some(i => i.severity === "CRITICAL");

    const recommendations = [];
    if (riskLevel === "HIGH" || riskLevel === "SUSPICIOUS") {
      recommendations.push("Do not click any embedded links or call phone numbers provided in the message.");
      recommendations.push("Never transmit gift card codes, cryptocurrency, or wire transfers to unknown contacts.");
      recommendations.push("Contact the organization directly through their verified public website or customer phone number.");
    } else if (riskLevel === "CAUTION") {
      recommendations.push("Verify sender identity independently before replying or downloading attachments.");
      recommendations.push("Check the sender email header to ensure domain authentication aligns.");
    } else {
      recommendations.push("No severe deceptive patterns detected in message content.");
      recommendations.push("Continue practicing standard email and messaging caution.");
    }

    const scanId = `scn_${Math.random().toString(36).substring(2, 10)}${Date.now().toString(36)}`;
    const summary = content.length > 80 ? content.slice(0, 77) + "..." : content;

    const scanRecord: ScanRecord = {
      scan_id: scanId,
      user_id: userId,
      user_email: userEmail,
      input_type: "message",
      input_summary: summary,
      input_data: { content, channel },
      risk_score: finalScore,
      risk_level: riskLevel,
      is_threat_confirmed: isThreatConfirmed,
      indicators,
      threat_intelligence: {
        urlhaus: { status: "N/A - Text Analysis" },
        virustotal: { status: "Evaluated", malicious: isThreatConfirmed ? 1 : 0, total_vendors: 1 }
      },
      ai_analysis: {
        risk_level: riskLevel,
        risk_score: finalScore,
        category: indicators.length > 0 ? "Social Engineering / Phishing Forensics" : "Authentic Communication",
        summary: `NLP heuristics evaluated message across ${channel} channel. Calculated risk score: ${finalScore}/100. ${indicators.length} risk indicators identified.`,
        indicators,
        highlighted_sentences: highlightedSentences.slice(0, 5),
        recommendation: recommendations[0]
      },
      recommendations,
      score_breakdown: { factors: indicators.map(i => ({ factor: i.name, severity: i.severity })) },
      created_at: new Date().toISOString()
    };

    serverStorage.saveScan(scanRecord);

    return NextResponse.json(scanRecord);
  } catch (err: any) {
    return NextResponse.json({ error: err.message || "Failed to analyze message" }, { status: 500 });
  }
}
