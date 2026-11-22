"use client";

import React, { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { 
  ShieldCheck, 
  ShieldAlert, 
  ShieldX, 
  Printer, 
  ArrowLeft, 
  ExternalLink, 
  Globe, 
  MessageSquareWarning, 
  Briefcase, 
  Activity, 
  Calendar, 
  User, 
  CheckCircle2, 
  AlertCircle,
  XCircle,
  HelpCircle,
  Building2,
  Info,
  FileText,
  Share2
} from "lucide-react";
import { api, ScanRecord } from "@/lib/api";
import RiskGauge from "@/components/RiskGauge";
import ThreatIntelMatrix from "@/components/ThreatIntelMatrix";
import SentenceHighlighter from "@/components/SentenceHighlighter";

export default function DetailedReportPage() {
  const params = useParams();
  const scanId = params?.scan_id as string;
  const router = useRouter();

  const [scan, setScan] = useState<ScanRecord | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!scanId) return;
    const fetchReport = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await api.getScan(scanId);
        setScan(data);
      } catch (err: any) {
        setError(err.message || "Failed to load scan report");
      } finally {
        setLoading(false);
      }
    };
    fetchReport();
  }, [scanId]);

  const handlePrint = () => {
    window.print();
  };

  if (loading) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-20 text-center space-y-4">
        <div className="w-12 h-12 rounded-full border-4 border-cyan-500/20 border-t-cyan-500 animate-spin mx-auto" />
        <p className="font-mono text-sm text-cyan-500">Retrieving Security Forensic Dossier for {scanId}...</p>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="max-w-3xl mx-auto px-4 py-16 text-center space-y-4">
        <AlertCircle className="w-12 h-12 text-rose-500 mx-auto" />
        <h2 className="text-xl font-bold text-slate-900 dark:text-white">Report Not Found</h2>
        <p className="text-xs text-slate-500">{error || "The requested scan ID does not exist or has expired."}</p>
        <Link
          href="/dashboard"
          className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-cyan-500 text-white text-xs font-semibold"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Return to Dashboard</span>
        </Link>
      </div>
    );
  }

  const isHigh = scan.risk_level === "HIGH";
  const isSuspicious = scan.risk_level === "SUSPICIOUS";
  const isCaution = scan.risk_level === "CAUTION";

  const TypeIcon = scan.input_type === "url" 
    ? Globe 
    : scan.input_type === "job" 
    ? Briefcase 
    : MessageSquareWarning;

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
      
      {/* Top Action Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-200 dark:border-slate-800">
        <div className="flex items-center gap-3">
          <button
            onClick={() => router.back()}
            className="p-2 rounded-lg border border-slate-200 dark:border-slate-800 hover:border-cyan-500 text-slate-500 transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <span className="text-[11px] font-mono text-cyan-500 font-bold tracking-widest uppercase">
              SECURITY AUDIT REPORT
            </span>
            <h1 className="text-xl sm:text-2xl font-extrabold text-slate-900 dark:text-white font-mono">
              {scan.scan_id}
            </h1>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handlePrint}
            className="flex items-center gap-1.5 px-4 py-2 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-cyber-900 text-xs font-semibold text-slate-700 dark:text-slate-300 hover:border-cyan-500 transition-colors shadow-sm"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Export PDF / Print</span>
          </button>
          <Link
            href={scan.input_type === "url" ? "/scan/url" : scan.input_type === "job" ? "/scan/job" : "/scan/message"}
            className="cyber-btn flex items-center gap-1.5 px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 text-white text-xs font-bold"
          >
            <span>Scan Another</span>
          </Link>
        </div>
      </div>

      {/* Main Report Body */}
      <div className="mt-8 space-y-8">
        
        {/* Executive Verdict Banner */}
        <div className="cyber-card p-6 rounded-2xl flex flex-col md:flex-row items-center justify-between gap-8 border-l-4 border-l-cyan-500">
          <div className="space-y-3 max-w-xl">
            <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
              <span className="px-2.5 py-0.5 rounded bg-slate-100 dark:bg-cyber-850 border border-slate-200 dark:border-slate-800 uppercase text-slate-600 dark:text-slate-400 font-semibold flex items-center gap-1">
                <TypeIcon className="w-3.5 h-3.5 text-cyan-500" />
                <span>{scan.input_type} Inspection</span>
              </span>
              <span className="text-slate-400">
                Created: {scan.created_at ? scan.created_at.replace("T", " ").substring(0, 19) : "Just now"}
              </span>
            </div>

            <h2 className="text-2xl font-extrabold text-slate-900 dark:text-white font-sans">
              {scan.ai_analysis?.category || "Comprehensive Fraud Assessment"}
            </h2>

            <div className="p-3 rounded-xl bg-slate-50 dark:bg-cyber-900 border border-slate-200 dark:border-slate-800 font-mono text-xs text-slate-700 dark:text-slate-300 break-all">
              Target: {scan.input_summary}
            </div>

            <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
              {scan.ai_analysis?.summary || "Unified threat intelligence and heuristic verification completed."}
            </p>
          </div>

          <RiskGauge
            score={scan.risk_score}
            level={scan.risk_level}
            isThreatConfirmed={scan.is_threat_confirmed}
            size="lg"
          />
        </div>

        {/* Risk Score Calculation & Weight Breakdown */}
        {scan.score_breakdown?.calculation_items && scan.score_breakdown.calculation_items.length > 0 && (
          <div className="cyber-card p-6 rounded-2xl space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-200 dark:border-slate-800">
              <h3 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-900 dark:text-white">
                Risk Score Calculation Audit (How {scan.risk_score}/100 was calculated)
              </h3>
              <span className="text-xs font-mono font-bold px-2.5 py-0.5 rounded bg-cyan-500/10 text-cyan-500 border border-cyan-500/30">
                Formula: Weighted Multi-Engine Signals
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-400 font-mono text-[11px] uppercase">
                    <th className="py-2 px-3">Evaluated Signal</th>
                    <th className="py-2 px-3">Point Weight</th>
                    <th className="py-2 px-3">Technical Evidence / Reasoning</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60 font-mono">
                  {scan.score_breakdown.calculation_items.map((item: any, idx: number) => (
                    <tr key={idx} className="hover:bg-slate-50/50 dark:hover:bg-slate-800/30 transition-colors">
                      <td className="py-2.5 px-3 font-semibold text-slate-900 dark:text-slate-200">
                        {item.factor}
                      </td>
                      <td className="py-2.5 px-3">
                        <span className="inline-block px-2 py-0.5 rounded text-[11px] font-bold bg-rose-500/15 text-rose-500 border border-rose-500/25">
                          +{item.points} pts
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-slate-600 dark:text-slate-400 font-sans">
                        {item.description}
                      </td>
                    </tr>
                  ))}
                  <tr className="font-bold bg-slate-50 dark:bg-slate-800/40">
                    <td className="py-2.5 px-3 text-slate-900 dark:text-white">
                      Calculated Total Risk Score
                    </td>
                    <td className="py-2.5 px-3 text-cyan-500">
                      {scan.risk_score} / 100
                    </td>
                    <td className="py-2.5 px-3 text-slate-500 dark:text-slate-400 font-sans">
                      Classified as {scan.risk_level} risk tier
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Threat Intelligence Layer */}
        {scan.threat_intelligence && scan.input_type !== "job" && (
          <div className="space-y-3">
            <h3 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-500">
              External Threat Intelligence Telemetry
            </h3>
            <ThreatIntelMatrix threatIntel={scan.threat_intelligence} />
          </div>
        )}

        {/* Job Forensic: Official Career Portal Verification */}
        {scan.input_data?.career_verification && (
          <div className="cyber-card p-6 rounded-2xl space-y-4 border-l-4 border-l-blue-500">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-200 dark:border-slate-800">
              <div className="flex items-center gap-2">
                <Briefcase className="w-4 h-4 text-blue-500" />
                <h3 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-900 dark:text-white">
                  Official Job Listing Verification ({scan.input_data.career_verification.portal_name || scan.input_data.company_name || "Corporate Portal"})
                </h3>
              </div>

              <div>
                {scan.input_data.career_verification.status === "Matching vacancy found" ? (
                  <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-bold bg-emerald-500/10 text-emerald-500 border border-emerald-500/30">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    Matching vacancy found
                  </span>
                ) : scan.input_data.career_verification.status === "No matching vacancy found" ? (
                  <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-bold bg-amber-500/10 text-amber-500 border border-amber-500/30">
                    <AlertCircle className="w-3.5 h-3.5" />
                    No matching vacancy found
                  </span>
                ) : scan.input_data.career_verification.status === "Official website unavailable" ? (
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

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-sans">
              <div className="md:col-span-2 space-y-2">
                <p className="text-slate-700 dark:text-slate-300 leading-relaxed font-sans">
                  {scan.input_data.career_verification.message}
                </p>
                {scan.input_data.career_verification.fee_policy && (
                  <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-700 dark:text-amber-400 text-xs font-sans space-y-1">
                    <span className="font-bold block uppercase tracking-wider text-[10px] font-mono">
                      Corporate Fee Policy Notice:
                    </span>
                    <span>{scan.input_data.career_verification.fee_policy}</span>
                  </div>
                )}
              </div>

              <div className="p-4 rounded-xl bg-slate-50 dark:bg-cyber-850 border border-slate-200 dark:border-slate-800 flex flex-col justify-between gap-3 font-mono">
                <div>
                  <span className="text-[10px] uppercase text-slate-400 block font-semibold">Official Careers Portal</span>
                  <span className="font-bold text-sm text-slate-900 dark:text-white mt-0.5 block">
                    {scan.input_data.career_verification.portal_name || scan.input_data.company_name || "Corporate Portal"}
                  </span>
                </div>

                {scan.input_data.career_verification.portal_url && (
                  <a
                    href={scan.input_data.career_verification.direct_search_url || scan.input_data.career_verification.portal_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-blue-500 hover:bg-blue-600 text-white font-sans text-xs font-semibold transition-colors"
                  >
                    <span>Search on {scan.input_data.career_verification.portal_name}</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Job Forensic: Company Domain Verification Matrix */}
        {scan.input_data?.domain_verification && (
          <div className="cyber-card p-6 rounded-2xl space-y-4">
            <h3 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
              <Building2 className="w-4 h-4 text-blue-500" />
              <span>Company Domain Consistency Verification</span>
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
              <div className="p-4 rounded-xl bg-slate-50 dark:bg-cyber-850 border border-slate-200 dark:border-slate-800">
                <span className="text-slate-400 text-[11px] block">Claimed Employer</span>
                <span className="font-bold text-sm text-slate-900 dark:text-white mt-1 block">
                  {scan.input_data.company_name || "Unspecified"}
                </span>
                <span className="text-[11px] text-slate-500 mt-1 block">
                  Expected: {scan.input_data.domain_verification.expected_domains?.join(", ") || "Corporate domain"}
                </span>
              </div>

              <div className="p-4 rounded-xl bg-slate-50 dark:bg-cyber-850 border border-slate-200 dark:border-slate-800">
                <span className="text-slate-400 text-[11px] block">Sender Email Domain</span>
                <span className="font-bold text-sm text-slate-900 dark:text-white mt-1 block">
                  {scan.input_data.domain_verification.email_domain ? `@${scan.input_data.domain_verification.email_domain}` : "No email provided"}
                </span>
                <span className="text-[11px] text-slate-500 mt-1 block">
                  {scan.input_data.domain_verification.domain_match_status || "UNKNOWN"}
                </span>
              </div>

              <div className="p-4 rounded-xl bg-slate-50 dark:bg-cyber-850 border border-slate-200 dark:border-slate-800">
                <span className="text-slate-400 text-[11px] block">Verification Status</span>
                <div className="mt-1">
                  {scan.input_data.domain_verification.domain_match_status === "VERIFIED_DOMAIN" ? (
                    <span className="inline-flex items-center gap-1 text-emerald-500 font-bold">
                      <CheckCircle2 className="w-3.5 h-3.5" /> Domain Verified
                    </span>
                  ) : scan.input_data.domain_verification.domain_match_status === "FREE_WEBMAIL_MISMATCH" ? (
                    <span className="inline-flex items-center gap-1 text-rose-500 font-bold">
                      <XCircle className="w-3.5 h-3.5" /> Webmail Impersonation
                    </span>
                  ) : scan.input_data.domain_verification.domain_match_status === "DOMAIN_MISMATCH" ? (
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
                  {scan.input_data.domain_verification.warning_reason || "Affiliation established"}
                </span>
              </div>
            </div>
          </div>
        )}

        {/* Job Forensic: Application Portal Telemetry */}
        {scan.input_data?.application_url_analysis && (
          <div className="cyber-card p-6 rounded-2xl space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-200 dark:border-slate-800">
              <div className="flex items-center gap-2">
                <Globe className="w-4 h-4 text-blue-500" />
                <h3 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-900 dark:text-white">
                  Application Portal Deep Telemetry
                </h3>
              </div>
              <span className={`px-2.5 py-0.5 rounded font-mono font-bold text-xs ${
                scan.input_data.application_url_analysis.risk_score >= 70 ? "bg-rose-500/15 text-rose-500 border border-rose-500/30" : "bg-amber-500/15 text-amber-500 border border-amber-500/30"
              }`}>
                Portal Risk: {scan.input_data.application_url_analysis.risk_score}/100 • {scan.input_data.application_url_analysis.risk_level}
              </span>
            </div>

            <div className="space-y-3 font-mono text-xs">
              <div className="p-3 rounded-xl bg-slate-50 dark:bg-cyber-850 border border-slate-200 dark:border-slate-800 break-all">
                <span className="text-slate-400 block text-[10px] uppercase font-semibold">Submitted Portal Link:</span>
                <span className="font-bold text-slate-900 dark:text-white text-xs">{scan.input_data.application_url_analysis.url}</span>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-3">
                <div className="p-3 rounded-xl bg-slate-50 dark:bg-cyber-850 border border-slate-200 dark:border-slate-800">
                  <span className="text-slate-400 block text-[10px]">Domain Age</span>
                  <span className="font-bold text-slate-900 dark:text-white text-xs mt-0.5 block truncate">
                    {scan.input_data.application_url_analysis.domain_age}
                  </span>
                </div>
                <div className="p-3 rounded-xl bg-slate-50 dark:bg-cyber-850 border border-slate-200 dark:border-slate-800">
                  <span className="text-slate-400 block text-[10px]">Brand Match</span>
                  <span className="font-bold text-slate-900 dark:text-white text-xs mt-0.5 block truncate">
                    {scan.input_data.application_url_analysis.brand_similarity}
                  </span>
                </div>
                <div className="p-3 rounded-xl bg-slate-50 dark:bg-cyber-850 border border-slate-200 dark:border-slate-800">
                  <span className="text-slate-400 block text-[10px]">DNS Status</span>
                  <span className="font-bold text-slate-900 dark:text-white text-xs mt-0.5 block truncate">
                    {scan.input_data.application_url_analysis.dns_status}
                  </span>
                </div>
                <div className="p-3 rounded-xl bg-slate-50 dark:bg-cyber-850 border border-slate-200 dark:border-slate-800">
                  <span className="text-slate-400 block text-[10px]">Host Type</span>
                  <span className="font-bold text-slate-900 dark:text-white text-xs mt-0.5 block truncate">
                    {scan.input_data.application_url_analysis.ip_classification}
                  </span>
                </div>
                <div className="p-3 rounded-xl bg-slate-50 dark:bg-cyber-850 border border-slate-200 dark:border-slate-800">
                  <span className="text-slate-400 block text-[10px]">VirusTotal</span>
                  <span className="font-bold text-slate-900 dark:text-white text-xs mt-0.5 block truncate">
                    {scan.input_data.application_url_analysis.virustotal}
                  </span>
                </div>
                <div className="p-3 rounded-xl bg-slate-50 dark:bg-cyber-850 border border-slate-200 dark:border-slate-800">
                  <span className="text-slate-400 block text-[10px]">Threat Feeds</span>
                  <span className="font-bold text-slate-900 dark:text-white text-xs mt-0.5 block truncate">
                    {scan.input_data.application_url_analysis.google_safe_browsing}
                  </span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Embedded URLs Deep Inspection */}
        {scan.input_data?.embedded_url_analyses && scan.input_data.embedded_url_analyses.length > 0 && (
          <div className="cyber-card p-6 rounded-2xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-200 dark:border-slate-800">
              <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase font-mono tracking-wider">
                Embedded URL Deep Forensics ({scan.input_data.embedded_url_analyses.length})
              </h3>
              <span className="text-xs font-mono text-slate-500">Autonomous Recursive Scans</span>
            </div>

            <div className="space-y-3">
              {scan.input_data.embedded_url_analyses.map((eu: any, idx: number) => {
                const isHigh = eu.risk_score >= 70 || eu.is_private_ip;
                return (
                  <div key={idx} className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-cyber-850 space-y-2 text-xs">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <span className="font-mono font-bold text-slate-900 dark:text-white break-all">{eu.url}</span>
                      <span className={`px-2 py-0.5 rounded font-mono font-bold text-[11px] whitespace-nowrap ${
                        isHigh ? "bg-rose-500/15 text-rose-500 border border-rose-500/30" : "bg-amber-500/15 text-amber-500 border border-amber-500/30"
                      }`}>
                        Score: {eu.risk_score}/100 • {eu.risk_level}
                      </span>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-2 pt-1 font-mono text-[11px]">
                      <div className="p-2 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                        <span className="text-slate-400 block text-[10px]">Host:</span>
                        <span className={`font-bold ${eu.is_private_ip ? "text-rose-500" : "text-slate-200"}`}>{eu.ip_classification}</span>
                      </div>
                      <div className="p-2 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                        <span className="text-slate-400 block text-[10px]">Protocol:</span>
                        <span className="font-bold text-slate-200">{eu.protocol} ({eu.is_https ? "Encrypted" : "Insecure"})</span>
                      </div>
                      <div className="p-2 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                        <span className="text-slate-400 block text-[10px]">VirusTotal:</span>
                        <span className="font-bold text-slate-200">
                          {eu.threat_intelligence?.virustotal?.malicious !== undefined
                            ? `${eu.threat_intelligence.virustotal.malicious}/${eu.threat_intelligence.virustotal.total_vendors || 60} Flagged`
                            : "Clean"}
                        </span>
                      </div>
                      <div className="p-2 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                        <span className="text-slate-400 block text-[10px]">Safe Browsing:</span>
                        <span className="font-bold text-slate-200">{eu.threat_intelligence?.google_safe_browsing?.is_threat_found ? "Threat" : "No Match"}</span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Evidence Highlighting (if message text available) */}
        {scan.input_data?.content && (
          <div className="cyber-card p-6 rounded-2xl space-y-4">
            <h3 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-900 dark:text-white">
              Inspected Message & Flagged Evidence Sentences
            </h3>
            <SentenceHighlighter
              content={scan.input_data.content}
              flaggedSentences={scan.ai_analysis?.highlighted_sentences || []}
            />
          </div>
        )}

        {/* Forensic Indicators List */}
        <div className="cyber-card p-6 rounded-2xl space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-200 dark:border-slate-800">
            <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase font-mono tracking-wider flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-500" />
              <span>Evidence Signals & Indicators ({scan.indicators?.length || 0})</span>
            </h3>
            <span className="text-xs font-mono text-slate-500">Deduplicated Heuristics</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {scan.indicators && scan.indicators.length > 0 ? (
              scan.indicators.map((ind, i) => {
                const isCrit = ind.severity === "CRITICAL" || ind.severity === "HIGH";
                return (
                  <div
                    key={i}
                    className={`p-3.5 rounded-xl border text-xs space-y-1 ${
                      isCrit 
                        ? "bg-rose-500/5 border-rose-500/25" 
                        : "bg-amber-500/5 border-amber-500/25"
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-slate-900 dark:text-white">{ind.name}</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                        isCrit ? "bg-rose-500 text-white" : "bg-amber-500 text-slate-900"
                      }`}>
                        {ind.severity}
                      </span>
                    </div>
                    <p className="text-slate-600 dark:text-slate-400 text-[11px] leading-relaxed">
                      {ind.evidence}
                    </p>
                  </div>
                );
              })
            ) : (
              <p className="text-xs text-slate-500 col-span-2 py-4 text-center">
                No adverse forensic indicators detected.
              </p>
            )}
          </div>
        </div>

        {/* Recommendations & Remediation */}
        <div className="cyber-card p-6 rounded-2xl space-y-4">
          <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase font-mono tracking-wider flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-500" />
            <span>Defensive Guidance & Recommended Protocol</span>
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
            {scan.recommendations?.map((rec, i) => (
              <div
                key={i}
                className="p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-cyber-850 flex items-start gap-2.5"
              >
                <CheckCircle2 className="w-4 h-4 text-emerald-500 flex-shrink-0 mt-0.5" />
                <span className="text-slate-700 dark:text-slate-300 font-medium leading-relaxed">
                  {rec}
                </span>
              </div>
            ))}
          </div>
        </div>

      </div>

    </div>
  );
}
