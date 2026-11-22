"use client";

import React, { useState, useEffect, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { 
  Briefcase, 
  Building2, 
  Mail, 
  Globe, 
  DollarSign, 
  FileText, 
  Activity, 
  ShieldAlert, 
  ShieldCheck, 
  ExternalLink,
  AlertCircle,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Phone,
  Video,
  CheckSquare,
  Square,
  Info,
  Server
} from "lucide-react";
import { api, ScanRecord } from "@/lib/api";
import RiskGauge from "@/components/RiskGauge";

function JobScannerContent() {
  const searchParams = useSearchParams();
  const initialDesc = searchParams.get("desc") || "";

  const [companyName, setCompanyName] = useState("");
  const [jobTitle, setJobTitle] = useState("");
  const [recruiterEmail, setRecruiterEmail] = useState("");
  const [jobDescription, setJobDescription] = useState(initialDesc);
  const [salaryOrTerms, setSalaryOrTerms] = useState("");
  const [applicationUrl, setApplicationUrl] = useState("");
  const [recruiterPhone, setRecruiterPhone] = useState("");
  const [interviewPlatform, setInterviewPlatform] = useState("");
  const [isUnsolicited, setIsUnsolicited] = useState(false);

  const [loading, setLoading] = useState(false);
  const [scanResult, setScanResult] = useState<ScanRecord | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleVerify = async () => {
    if (!companyName.trim() && !jobDescription.trim()) {
      setError("Please provide at least a Company Name or Job Description.");
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const result = await api.scanJob({
        company_name: companyName,
        job_title: jobTitle,
        recruiter_email: recruiterEmail,
        job_description: jobDescription,
        salary_or_terms: salaryOrTerms,
        application_url: applicationUrl,
        recruiter_phone: recruiterPhone,
        interview_platform: interviewPlatform,
        is_unsolicited: isUnsolicited
      });
      setScanResult(result);
    } catch (err: any) {
      setError(err.message || "Failed to verify recruitment offer");
    } finally {
      setLoading(false);
    }
  };

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    handleVerify();
  };

  const domainVer = scanResult?.input_data?.domain_verification;
  const careerVer = scanResult?.input_data?.career_verification;
  const appUrlAnalysis = scanResult?.input_data?.application_url_analysis;
  const scoreBreakdown = scanResult?.score_breakdown;

  // Separate primary fraud indicators from supporting evidence
  const primaryIndicators = scanResult?.indicators?.filter(ind => ind.category !== "Supporting Evidence") || [];
  const supportingIndicators = scanResult?.indicators?.filter(ind => ind.category === "Supporting Evidence") || [];

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
      
      {/* Title */}
      <div className="text-center max-w-2xl mx-auto space-y-3 mb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-blue-500/30 bg-blue-500/10 text-blue-600 dark:text-blue-400 text-xs font-mono font-semibold">
          <Briefcase className="w-3.5 h-3.5" />
          <span>RECRUITMENT FRAUD & COMPANY DOMAIN VERIFICATION</span>
        </div>
        <h1 className="text-3xl font-extrabold text-slate-900 dark:text-white">
          Fake Job & Recruiter Verifier
        </h1>
        <p className="text-xs sm:text-sm text-slate-500">
          Cross-references recruiter domains with legitimate corporate registries, detects advance fee scams, and analyzes recruitment claims.
        </p>
      </div>

      {/* Input Form */}
      <div className="cyber-card p-6 rounded-2xl shadow-xl mb-8">
        <form onSubmit={onSubmit} className="space-y-4">
          
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            
            {/* Company Name */}
            <div>
              <label className="block text-xs font-mono uppercase tracking-wider text-slate-500 font-semibold mb-1">
                Claimed Company Name *
              </label>
              <div className="relative flex items-center">
                <Building2 className="w-4 h-4 text-slate-400 absolute left-3" />
                <input
                  type="text"
                  list="top-companies"
                  value={companyName}
                  onChange={(e) => setCompanyName(e.target.value)}
                  placeholder="e.g. Microsoft, Google, Amazon, Meta, Deloitte..."
                  className="w-full pl-10 pr-3 py-2.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-cyber-900 text-sm font-sans text-slate-900 dark:text-white focus:outline-none focus:border-blue-500"
                />
                <datalist id="top-companies">
                  <option value="Google" />
                  <option value="Microsoft" />
                  <option value="Amazon" />
                  <option value="Apple" />
                  <option value="Meta" />
                  <option value="Netflix" />
                  <option value="IBM" />
                  <option value="Cisco" />
                  <option value="Oracle" />
                  <option value="Intel" />
                  <option value="Adobe" />
                  <option value="Salesforce" />
                  <option value="Spotify" />
                  <option value="Uber" />
                  <option value="Airbnb" />
                  <option value="PayPal" />
                  <option value="Stripe" />
                  <option value="Twitter" />
                  <option value="LinkedIn" />
                  <option value="TikTok" />
                  <option value="McKinsey" />
                  <option value="BCG" />
                  <option value="Bain" />
                  <option value="Deloitte" />
                  <option value="PwC" />
                  <option value="EY" />
                  <option value="KPMG" />
                  <option value="JPMorgan Chase" />
                  <option value="Goldman Sachs" />
                  <option value="Morgan Stanley" />
                  <option value="HSBC" />
                  <option value="Citi" />
                  <option value="Barclays" />
                  <option value="Bank of America" />
                  <option value="HBL" />
                  <option value="UBL" />
                  <option value="Meezan Bank" />
                  <option value="MCB" />
                  <option value="Jazz" />
                  <option value="Telenor" />
                  <option value="Zong" />
                  <option value="Systems Limited" />
                  <option value="10Pearls" />
                  <option value="NetSol" />
                  <option value="Careem" />
                  <option value="Daraz" />
                </datalist>
              </div>
            </div>

            {/* Recruiter Email */}
            <div>
              <label className="block text-xs font-mono uppercase tracking-wider text-slate-500 font-semibold mb-1">
                Recruiter / Sender Email Address
              </label>
              <div className="relative flex items-center">
                <Mail className="w-4 h-4 text-slate-400 absolute left-3" />
                <input
                  type="email"
                  value={recruiterEmail}
                  onChange={(e) => setRecruiterEmail(e.target.value)}
                  placeholder="e.g. microsoft.hr2026@gmail.com"
                  className="w-full pl-10 pr-3 py-2.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-cyber-900 text-sm font-mono text-slate-900 dark:text-white focus:outline-none focus:border-blue-500"
                />
              </div>
            </div>

            {/* Job Title */}
            <div>
              <label className="block text-xs font-mono uppercase tracking-wider text-slate-500 font-semibold mb-1">
                Job Title / Position
              </label>
              <div className="relative flex items-center">
                <Briefcase className="w-4 h-4 text-slate-400 absolute left-3" />
                <input
                  type="text"
                  value={jobTitle}
                  onChange={(e) => setJobTitle(e.target.value)}
                  placeholder="e.g. Software Engineer Intern"
                  className="w-full pl-10 pr-3 py-2.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-cyber-900 text-sm font-sans text-slate-900 dark:text-white focus:outline-none focus:border-blue-500"
                />
              </div>
            </div>

            {/* Salary / Terms */}
            <div>
              <label className="block text-xs font-mono uppercase tracking-wider text-slate-500 font-semibold mb-1">
                Salary / Fee Mentioned
              </label>
              <div className="relative flex items-center">
                <DollarSign className="w-4 h-4 text-slate-400 absolute left-3" />
                <input
                  type="text"
                  value={salaryOrTerms}
                  onChange={(e) => setSalaryOrTerms(e.target.value)}
                  placeholder="e.g. PKR 2,000 fee, $5,000/week"
                  className="w-full pl-10 pr-3 py-2.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-cyber-900 text-sm font-sans text-slate-900 dark:text-white focus:outline-none focus:border-blue-500"
                />
              </div>
            </div>

            {/* Recruiter Phone / WhatsApp */}
            <div>
              <label className="block text-xs font-mono uppercase tracking-wider text-slate-500 font-semibold mb-1">
                Recruiter Phone / WhatsApp Number
              </label>
              <div className="relative flex items-center">
                <Phone className="w-4 h-4 text-slate-400 absolute left-3" />
                <input
                  type="text"
                  value={recruiterPhone}
                  onChange={(e) => setRecruiterPhone(e.target.value)}
                  placeholder="e.g. +1 (555) 234-5678 or +92 300 1234567"
                  className="w-full pl-10 pr-3 py-2.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-cyber-900 text-sm font-mono text-slate-900 dark:text-white focus:outline-none focus:border-blue-500"
                />
              </div>
            </div>

            {/* Interview Medium / Platform */}
            <div>
              <label className="block text-xs font-mono uppercase tracking-wider text-slate-500 font-semibold mb-1">
                Interview Platform / Channel
              </label>
              <div className="relative flex items-center">
                <Video className="w-4 h-4 text-slate-400 absolute left-3" />
                <select
                  value={interviewPlatform}
                  onChange={(e) => setInterviewPlatform(e.target.value)}
                  className="w-full pl-10 pr-3 py-2.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-cyber-900 text-sm font-sans text-slate-900 dark:text-white focus:outline-none focus:border-blue-500"
                >
                  <option value="">Select Interview Method...</option>
                  <option value="Official Corporate Video (Meet, Teams, Zoom)">Official Corporate Video (Meet, Teams, Zoom)</option>
                  <option value="Telegram / Text Messaging Chat">Telegram / Text Messaging Chat (High Risk Indicator)</option>
                  <option value="WhatsApp Messaging Chat">WhatsApp Messaging Chat</option>
                  <option value="Signal Messenger">Signal Messenger</option>
                  <option value="In-Person Corporate Office">In-Person Corporate Office</option>
                  <option value="No Interview Conducted (Immediate Offer)">No Interview Conducted (Immediate Offer)</option>
                </select>
              </div>
            </div>

          </div>

          {/* Application URL & Unsolicited Checkbox */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-mono uppercase tracking-wider text-slate-500 font-semibold mb-1">
                Application Portal or Form Link
              </label>
              <div className="relative flex items-center">
                <Globe className="w-4 h-4 text-slate-400 absolute left-3" />
                <input
                  type="text"
                  value={applicationUrl}
                  onChange={(e) => setApplicationUrl(e.target.value)}
                  placeholder="e.g. https://forms.gle/xyz or external link"
                  className="w-full pl-10 pr-3 py-2.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-cyber-900 text-sm font-mono text-slate-900 dark:text-white focus:outline-none focus:border-blue-500"
                />
              </div>
            </div>

            <div className="flex items-end pb-1">
              <label 
                onClick={() => setIsUnsolicited(!isUnsolicited)}
                className="flex items-center gap-2.5 p-2.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-cyber-900 w-full cursor-pointer hover:border-blue-500 transition-colors"
              >
                {isUnsolicited ? (
                  <CheckSquare className="w-4 h-4 text-blue-500 flex-shrink-0" />
                ) : (
                  <Square className="w-4 h-4 text-slate-400 flex-shrink-0" />
                )}
                <span className="text-xs text-slate-700 dark:text-slate-300 font-medium select-none">
                  Unsolicited contact (I did not apply for this position)
                </span>
              </label>
            </div>
          </div>

          {/* Job Description Text */}
          <div>
            <label className="block text-xs font-mono uppercase tracking-wider text-slate-500 font-semibold mb-1">
              Job Offer / Message Text *
            </label>
            <textarea
              rows={4}
              value={jobDescription}
              onChange={(e) => setJobDescription(e.target.value)}
              placeholder="Paste the full job advertisement or recruitment offer text..."
              className="w-full p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-cyber-900 text-sm font-sans text-slate-900 dark:text-white focus:outline-none focus:border-blue-500"
            />
          </div>

          {/* Action Row */}
          <div className="flex items-center justify-end pt-2">
            <button
              type="submit"
              disabled={loading || (!companyName.trim() && !jobDescription.trim())}
              className="cyber-btn flex items-center justify-center gap-2 px-6 py-2.5 rounded-xl bg-gradient-to-r from-blue-500 to-cyan-600 text-white font-semibold text-xs shadow-md shadow-blue-500/25 disabled:opacity-50"
            >
              {loading ? (
                <span className="flex items-center gap-1.5 font-mono">
                  <Activity className="w-3.5 h-3.5 animate-spin" /> Verifying Credentials...
                </span>
              ) : (
                <span>Verify Job Offer</span>
              )}
            </button>
          </div>

        </form>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="p-4 rounded-xl border border-rose-500/30 bg-rose-500/10 text-rose-500 text-xs font-mono mb-8">
          Verification Error: {error}
        </div>
      )}

      {/* Results View */}
      {scanResult && !loading && (
        <div className="space-y-6">
          
          {/* Executive Summary */}
          <div className="cyber-card p-6 rounded-2xl flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="space-y-2 max-w-lg">
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono uppercase tracking-wider font-semibold text-blue-500">
                  Scan ID: {scanResult.scan_id}
                </span>
                <span className="text-slate-400 text-xs font-mono">
                  Target: {scanResult.input_summary}
                </span>
              </div>
              <h2 className="text-xl font-bold text-slate-900 dark:text-white font-sans">
                {scanResult.ai_analysis?.category || "Recruitment Verification Assessment"}
              </h2>
              <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                {scanResult.ai_analysis?.summary || "Completed corporate domain verification and advance fee analysis."}
              </p>
              <div className="pt-2">
                <Link
                  href={`/report/${scanResult.scan_id}`}
                  className="inline-flex items-center gap-1.5 text-xs font-bold text-blue-500 hover:text-blue-400"
                >
                  <span>Open Full Forensic Report</span>
                  <ExternalLink className="w-3.5 h-3.5" />
                </Link>
              </div>
            </div>

            <RiskGauge
              score={scanResult.risk_score}
              level={scanResult.risk_level}
              isThreatConfirmed={scanResult.is_threat_confirmed}
              size="md"
            />
          </div>

          {/* Official Job Listing Verification Card */}
          {careerVer && (
            <div className="cyber-card p-6 rounded-2xl space-y-4 border-l-4 border-l-blue-500">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-200 dark:border-slate-800">
                <div className="flex items-center gap-2">
                  <Briefcase className="w-4 h-4 text-blue-500" />
                  <h3 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-900 dark:text-white">
                    Official Job Listing Verification
                  </h3>
                </div>

                {/* Status Badge - 4 distinct outcomes */}
                <div>
                  {careerVer.status === "Matching vacancy found" ? (
                    <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-bold bg-emerald-500/10 text-emerald-500 border border-emerald-500/30">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      Matching vacancy found
                    </span>
                  ) : careerVer.status === "No matching vacancy found" ? (
                    <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-bold bg-amber-500/10 text-amber-500 border border-amber-500/30">
                      <AlertCircle className="w-3.5 h-3.5" />
                      No matching vacancy found
                    </span>
                  ) : careerVer.status === "Official website unavailable" ? (
                    <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-bold bg-rose-500/10 text-rose-500 border border-rose-500/30">
                      <XCircle className="w-3.5 h-3.5" />
                      Official website unavailable
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-bold bg-slate-500/10 text-slate-400 border border-slate-500/30">
                      <HelpCircle className="w-3.5 h-3.5" />
                      Verification not performed
                    </span>
                  )}
                </div>
              </div>

              {/* Assessment Message & Portal Link */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-sans">
                <div className="md:col-span-2 space-y-2">
                  <p className="text-slate-700 dark:text-slate-300 leading-relaxed font-sans">
                    {careerVer.message}
                  </p>
                  {careerVer.fee_policy && (
                    <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-700 dark:text-amber-400 text-xs font-sans space-y-1">
                      <span className="font-bold block uppercase tracking-wider text-[10px] font-mono">
                        Corporate Fee Policy Notice:
                      </span>
                      <span>{careerVer.fee_policy}</span>
                    </div>
                  )}
                </div>

                <div className="p-4 rounded-xl bg-slate-50 dark:bg-cyber-850 border border-slate-200 dark:border-slate-800 flex flex-col justify-between gap-3 font-mono">
                  <div>
                    <span className="text-[10px] uppercase text-slate-400 block font-semibold">Official Careers Portal</span>
                    <span className="font-bold text-sm text-slate-900 dark:text-white mt-0.5 block">
                      {careerVer.portal_name || companyName || "Corporate Portal"}
                    </span>
                  </div>

                  {careerVer.portal_url ? (
                    <a
                      href={careerVer.direct_search_url || careerVer.portal_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-blue-500 hover:bg-blue-600 text-white font-sans text-xs font-semibold transition-colors"
                    >
                      <span>Search on {careerVer.portal_name}</span>
                      <ExternalLink className="w-3.5 h-3.5" />
                    </a>
                  ) : (
                    <span className="text-slate-500 text-[11px]">Manual portal search recommended</span>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Domain Verification Matrix */}
          <div className="cyber-card p-6 rounded-2xl space-y-4">
            <h3 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
              <Building2 className="w-4 h-4 text-blue-500" />
              <span>Company Domain Consistency Verification</span>
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
              <div className="p-4 rounded-xl bg-slate-50 dark:bg-cyber-850 border border-slate-200 dark:border-slate-800">
                <span className="text-slate-400 text-[11px] block">Claimed Employer</span>
                <span className="font-bold text-sm text-slate-900 dark:text-white mt-1 block">
                  {companyName || "Unspecified"}
                </span>
                <span className="text-[11px] text-slate-500 mt-1 block">
                  Expected: {domainVer?.expected_domains?.join(", ") || "Corporate domain"}
                </span>
              </div>

              <div className="p-4 rounded-xl bg-slate-50 dark:bg-cyber-850 border border-slate-200 dark:border-slate-800">
                <span className="text-slate-400 text-[11px] block">Sender Email Domain</span>
                <span className="font-bold text-sm text-slate-900 dark:text-white mt-1 block">
                  {domainVer?.email_domain ? `@${domainVer.email_domain}` : "No email provided"}
                </span>
                <span className="text-[11px] text-slate-500 mt-1 block">
                  {domainVer?.domain_match_status || "UNKNOWN"}
                </span>
              </div>

              <div className="p-4 rounded-xl bg-slate-50 dark:bg-cyber-850 border border-slate-200 dark:border-slate-800">
                <span className="text-slate-400 text-[11px] block">Verification Status</span>
                <div className="mt-1">
                  {domainVer?.domain_match_status === "VERIFIED_DOMAIN" ? (
                    <span className="inline-flex items-center gap-1 text-emerald-500 font-bold">
                      <CheckCircle2 className="w-3.5 h-3.5" /> Domain Verified
                    </span>
                  ) : domainVer?.domain_match_status === "FREE_WEBMAIL_MISMATCH" ? (
                    <span className="inline-flex items-center gap-1 text-rose-500 font-bold">
                      <XCircle className="w-3.5 h-3.5" /> Webmail Impersonation
                    </span>
                  ) : domainVer?.domain_match_status === "DOMAIN_MISMATCH" ? (
                    <span className="inline-flex items-center gap-1 text-rose-500 font-bold">
                      <XCircle className="w-3.5 h-3.5" /> Domain Mismatch
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-amber-500 font-bold">
                      <AlertCircle className="w-3.5 h-3.5" /> Unverified Third-Party
                    </span>
                  )}
                </div>
                <span className="text-[11px] text-slate-500 mt-1 block truncate">
                  {domainVer?.warning_reason || "Affiliation established"}
                </span>
              </div>
            </div>
          </div>

          {/* Application Portal Deep Forensics Telemetry */}
          {appUrlAnalysis && (
            <div className="cyber-card p-6 rounded-2xl space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-200 dark:border-slate-800">
                <div className="flex items-center gap-2">
                  <Globe className="w-4 h-4 text-blue-500" />
                  <h3 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-900 dark:text-white">
                    Application Portal Deep Telemetry
                  </h3>
                </div>
                <span className={`px-2.5 py-0.5 rounded font-mono font-bold text-xs ${
                  appUrlAnalysis.risk_score >= 70 ? "bg-rose-500/15 text-rose-500 border border-rose-500/30" : "bg-amber-500/15 text-amber-500 border border-amber-500/30"
                }`}>
                  Portal Risk: {appUrlAnalysis.risk_score}/100 • {appUrlAnalysis.risk_level}
                </span>
              </div>

              <div className="space-y-3 font-mono text-xs">
                <div className="p-3 rounded-xl bg-slate-50 dark:bg-cyber-850 border border-slate-200 dark:border-slate-800 break-all">
                  <span className="text-slate-400 block text-[10px] uppercase font-semibold">Submitted Portal Link:</span>
                  <span className="font-bold text-slate-900 dark:text-white text-xs">{appUrlAnalysis.url}</span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-3">
                  <div className="p-3 rounded-xl bg-slate-50 dark:bg-cyber-850 border border-slate-200 dark:border-slate-800">
                    <span className="text-slate-400 block text-[10px]">Domain Age</span>
                    <span className="font-bold text-slate-900 dark:text-white text-xs mt-0.5 block truncate">
                      {appUrlAnalysis.domain_age}
                    </span>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-50 dark:bg-cyber-850 border border-slate-200 dark:border-slate-800">
                    <span className="text-slate-400 block text-[10px]">Brand Match</span>
                    <span className="font-bold text-slate-900 dark:text-white text-xs mt-0.5 block truncate">
                      {appUrlAnalysis.brand_similarity}
                    </span>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-50 dark:bg-cyber-850 border border-slate-200 dark:border-slate-800">
                    <span className="text-slate-400 block text-[10px]">DNS Status</span>
                    <span className="font-bold text-slate-900 dark:text-white text-xs mt-0.5 block truncate">
                      {appUrlAnalysis.dns_status}
                    </span>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-50 dark:bg-cyber-850 border border-slate-200 dark:border-slate-800">
                    <span className="text-slate-400 block text-[10px]">Host Type</span>
                    <span className="font-bold text-slate-900 dark:text-white text-xs mt-0.5 block truncate">
                      {appUrlAnalysis.ip_classification}
                    </span>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-50 dark:bg-cyber-850 border border-slate-200 dark:border-slate-800">
                    <span className="text-slate-400 block text-[10px]">VirusTotal</span>
                    <span className="font-bold text-slate-900 dark:text-white text-xs mt-0.5 block truncate">
                      {appUrlAnalysis.virustotal}
                    </span>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-50 dark:bg-cyber-850 border border-slate-200 dark:border-slate-800">
                    <span className="text-slate-400 block text-[10px]">Threat Feeds</span>
                    <span className="font-bold text-slate-900 dark:text-white text-xs mt-0.5 block truncate">
                      {appUrlAnalysis.google_safe_browsing}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Grouped Forensic Warning Signals & Supporting Evidence */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            
            {/* Primary Fraud Indicators */}
            <div className="cyber-card p-5 rounded-2xl space-y-3">
              <h4 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-900 dark:text-white flex items-center justify-between">
                <span className="flex items-center gap-1.5 text-rose-500">
                  <ShieldAlert className="w-4 h-4" />
                  Primary Recruitment Signals ({primaryIndicators.length})
                </span>
                <span className="text-[10px] text-slate-400 font-mono font-normal">Consolidated Evidence</span>
              </h4>

              <div className="space-y-3">
                {primaryIndicators.length > 0 ? (
                  primaryIndicators.map((ind, i) => (
                    <div key={i} className="p-3.5 rounded-xl border border-rose-500/20 bg-rose-500/5 text-xs space-y-1.5">
                      <div className="flex justify-between items-center">
                        <span className="font-bold text-slate-900 dark:text-white">{ind.name}</span>
                        <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-500 font-bold">
                          {ind.severity}
                        </span>
                      </div>
                      <p className="text-slate-600 dark:text-slate-300 text-xs">{ind.evidence}</p>

                      {/* Sub-signals breakdown if present */}
                      {ind.sub_signals && ind.sub_signals.length > 0 && (
                        <div className="pt-1.5 border-t border-rose-500/10 space-y-1">
                          {ind.sub_signals.map((sub: string, sIdx: number) => (
                            <div key={sIdx} className="flex items-start gap-1.5 text-[11px] text-slate-500 dark:text-slate-400">
                              <span className="w-1 h-1 rounded-full bg-rose-400 mt-1.5 flex-shrink-0" />
                              <span>{sub}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  ))
                ) : (
                  <p className="text-xs text-slate-500 py-3">No primary recruitment fraud signatures identified.</p>
                )}
              </div>
            </div>

            {/* Supporting Evidence & Anomalies */}
            <div className="cyber-card p-5 rounded-2xl space-y-3">
              <h4 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-900 dark:text-white flex items-center justify-between">
                <span className="flex items-center gap-1.5 text-amber-500">
                  <Info className="w-4 h-4" />
                  Supporting Evidence & Anomalies ({supportingIndicators.length})
                </span>
                <span className="text-[10px] text-slate-400 font-mono font-normal">Secondary Context</span>
              </h4>

              <div className="space-y-3">
                {supportingIndicators.length > 0 ? (
                  supportingIndicators.map((ind, i) => (
                    <div key={i} className="p-3 rounded-xl border border-amber-500/20 bg-amber-500/5 text-xs space-y-1">
                      <div className="flex justify-between items-center">
                        <span className="font-bold text-slate-900 dark:text-white">{ind.name}</span>
                        <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-500 font-bold">
                          {ind.severity}
                        </span>
                      </div>
                      <p className="text-slate-600 dark:text-slate-400 text-xs">{ind.evidence}</p>
                    </div>
                  ))
                ) : (
                  <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-cyber-850 text-xs text-slate-500 space-y-1">
                    <p className="font-semibold text-slate-700 dark:text-slate-300">No secondary anomalies recorded.</p>
                    <p>Phone numbers, interview platform, and compensation claims did not trigger behavioral warnings.</p>
                  </div>
                )}

                {/* Additional contextual parameters */}
                <div className="p-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-cyber-850 font-mono text-[11px] space-y-1.5">
                  <div className="flex justify-between">
                    <span className="text-slate-400">Phone Analysis:</span>
                    <span className="font-bold text-slate-700 dark:text-slate-300">{recruiterPhone ? "Contact logged" : "Not provided"}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Interview Medium:</span>
                    <span className="font-bold text-slate-700 dark:text-slate-300">{interviewPlatform || "Unspecified"}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Unsolicited Contact:</span>
                    <span className="font-bold text-slate-700 dark:text-slate-300">{isUnsolicited ? "Yes (Cold Outreach)" : "No"}</span>
                  </div>
                </div>
              </div>
            </div>

          </div>

          {/* Risk Score Calculation Audit Table */}
          {scoreBreakdown?.calculation_items && scoreBreakdown.calculation_items.length > 0 && (
            <div className="cyber-card p-6 rounded-2xl space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-200 dark:border-slate-800">
                <div className="flex items-center gap-2">
                  <Activity className="w-4 h-4 text-blue-500" />
                  <h3 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-900 dark:text-white">
                    Risk Score Calculation Audit (How {scanResult.risk_score}/100 was calculated)
                  </h3>
                </div>
                <span className="text-xs font-mono font-bold px-2.5 py-0.5 rounded bg-blue-500/10 text-blue-500 border border-blue-500/30">
                  Evidence-Weighted Valuation
                </span>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-xs">
                  <thead>
                    <tr className="border-b border-slate-200 dark:border-slate-800 text-[11px] text-slate-400 uppercase">
                      <th className="py-2 px-3">Evaluated Factor</th>
                      <th className="py-2 px-3">Weighted Impact</th>
                      <th className="py-2 px-3">Forensic Rationale</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                    {scoreBreakdown.calculation_items.map((item: any, idx: number) => (
                      <tr key={idx} className="hover:bg-slate-50 dark:hover:bg-cyber-850/50 transition-colors">
                        <td className="py-2.5 px-3 font-bold text-slate-900 dark:text-white whitespace-nowrap">
                          {item.factor}
                        </td>
                        <td className="py-2.5 px-3">
                          <span className={`px-2 py-0.5 rounded font-bold ${
                            item.points > 0 ? "bg-rose-500/10 text-rose-500" : "bg-emerald-500/10 text-emerald-500"
                          }`}>
                            {item.points > 0 ? `+${item.points}` : item.points} pts
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-slate-600 dark:text-slate-400 font-sans text-xs">
                          {item.description}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Defensive Guidance & Recommended Protocol */}
          <div className="cyber-card p-6 rounded-2xl space-y-4">
            <h4 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
              <ShieldCheck className="w-4 h-4 text-emerald-500" />
              <span>Recommended Defensive Actions</span>
            </h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              {scanResult.recommendations?.map((rec, i) => (
                <div key={i} className="flex items-start gap-2.5 p-3.5 rounded-xl bg-slate-50 dark:bg-cyber-850 border border-slate-200 dark:border-slate-800">
                  <CheckCircle2 className="w-4 h-4 text-emerald-500 mt-0.5 flex-shrink-0" />
                  <span className="text-slate-700 dark:text-slate-300 font-medium leading-relaxed">{rec}</span>
                </div>
              ))}
            </div>
          </div>

        </div>
      )}

    </div>
  );
}

export default function JobScannerPage() {
  return (
    <Suspense fallback={<div className="p-10 text-center font-mono text-blue-500">Loading Job Scanner...</div>}>
      <JobScannerContent />
    </Suspense>
  );
}
