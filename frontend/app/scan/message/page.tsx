"use client";

import React, { useState, useEffect, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { 
  MessageSquareWarning, 
  Mail, 
  MessageCircle, 
  Smartphone, 
  Send, 
  Activity, 
  ShieldAlert, 
  ShieldCheck, 
  ExternalLink,
  Layers,
  Globe,
  Lock,
  Unlock,
  Server,
  Database,
  Hash,
  AlertTriangle,
  FileWarning,
  CheckCircle2,
  XCircle
} from "lucide-react";
import { api, ScanRecord } from "@/lib/api";
import RiskGauge from "@/components/RiskGauge";
import SentenceHighlighter from "@/components/SentenceHighlighter";

function MessageScannerContent() {
  const searchParams = useSearchParams();
  const initialContent = searchParams.get("content") || "";
  const [content, setContent] = useState(initialContent);
  const [channel, setChannel] = useState("Email");
  const [loading, setLoading] = useState(false);
  const [scanResult, setScanResult] = useState<ScanRecord | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (initialContent) {
      handleAnalyze(initialContent, channel);
    }
  }, [initialContent]);

  const handleAnalyze = async (text: string, chan: string) => {
    const cleanText = text.trim();
    if (!cleanText) return;

    setLoading(true);
    setError(null);
    try {
      const result = await api.scanMessage(cleanText, chan);
      setScanResult(result);
    } catch (err: any) {
      setError(err.message || "Failed to analyze message");
    } finally {
      setLoading(false);
    }
  };

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    handleAnalyze(content, channel);
  };

  const embeddedUrls = scanResult?.input_data?.embedded_url_analyses || [];
  const headerAnalysis = scanResult?.input_data?.header_analysis;
  const validationSummary = scanResult?.input_data?.validation_summary;
  const calculationItems = scanResult?.score_breakdown?.calculation_items || [];

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
      
      {/* Title Header */}
      <div className="text-center max-w-2xl mx-auto space-y-3 mb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-purple-500/30 bg-purple-500/10 text-purple-600 dark:text-purple-400 text-xs font-mono font-semibold">
          <MessageSquareWarning className="w-3.5 h-3.5" />
          <span>MULTI-SOURCE SOCIAL ENGINEERING &amp; PHISHING SCANNER</span>
        </div>
        <h1 className="text-3xl font-extrabold text-slate-900 dark:text-white">
          Message &amp; Social Engineering Scanner
        </h1>
        <p className="text-xs sm:text-sm text-slate-500">
          Evaluates messages for credential harvesting, coercive account suspension, embedded private/suspicious links, sender mismatch, and validates consistency.
        </p>
      </div>

      {/* Input Form */}
      <div className="cyber-card p-6 rounded-2xl shadow-xl mb-8 space-y-4">
        <form onSubmit={onSubmit} className="space-y-4">
          
          {/* Channel selector */}
          <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-slate-200 dark:border-slate-800">
            <span className="text-xs font-mono text-slate-500 uppercase tracking-wider font-semibold">
              Select Communication Medium:
            </span>
            <div className="flex items-center gap-1.5">
              {[
                { name: "Email", icon: Mail },
                { name: "WhatsApp", icon: MessageCircle },
                { name: "SMS", icon: Smartphone },
                { name: "Social DM", icon: Send },
              ].map((c) => {
                const Icon = c.icon;
                const isSelected = channel === c.name;
                return (
                  <button
                    key={c.name}
                    type="button"
                    onClick={() => setChannel(c.name)}
                    className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
                      isSelected
                        ? "bg-purple-500 text-white shadow-sm shadow-purple-500/30 font-bold"
                        : "bg-slate-100 dark:bg-cyber-900 text-slate-600 dark:text-slate-400 hover:text-purple-400"
                    }`}
                  >
                    <Icon className="w-3.5 h-3.5" />
                    <span>{c.name}</span>
                  </button>
                );
              })}
            </div>
          </div>

          <div>
            <textarea
              rows={5}
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder="Paste email headers and text, SMS body, or WhatsApp message here..."
              className="w-full p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-cyber-900 text-sm font-sans text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:border-purple-500 transition-colors resize-y leading-relaxed"
            />
          </div>

          <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
            <span className="text-[11px] font-mono text-slate-400">
              Auto-extracts and scans embedded links, headers, and social engineering coercion.
            </span>
            <button
              type="submit"
              disabled={loading || !content.trim()}
              className="cyber-btn w-full sm:w-auto px-7 py-3 rounded-xl bg-gradient-to-r from-purple-500 to-indigo-600 text-white font-semibold text-sm shadow-md shadow-purple-500/25 disabled:opacity-50 flex items-center justify-center gap-2 whitespace-nowrap cursor-pointer transition-all"
            >
              {loading ? (
                <span className="flex items-center gap-2 font-mono">
                  <Activity className="w-4 h-4 animate-spin" /> Analyzing Phishing Vectors...
                </span>
              ) : (
                <span>Analyze Message</span>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="p-4 rounded-xl border border-rose-500/30 bg-rose-500/10 text-rose-500 text-xs font-mono mb-8">
          Scan Error: {error}
        </div>
      )}

      {/* Results View */}
      {scanResult && !loading && (
        <div className="space-y-6 animate-fadeIn">
          
          {/* Executive Summary Card */}
          <div className="cyber-card p-6 sm:p-8 rounded-2xl flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="space-y-3 max-w-lg text-left">
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono uppercase tracking-wider font-semibold text-purple-500">
                  SCAN ID: {scanResult.scan_id}
                </span>
                <span className="text-slate-400 text-xs font-mono">
                  Channel: {scanResult.input_data?.channel || channel}
                </span>
              </div>
              <h2 className="text-xl font-bold text-slate-900 dark:text-white font-sans">
                {scanResult.ai_analysis?.category || "Forensic Phishing Assessment"}
              </h2>
              <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                {scanResult.ai_analysis?.summary || "Completed heuristic, threat intel, and consistency validation inspection."}
              </p>
              <div className="pt-2">
                <Link
                  href={`/report/${scanResult.scan_id}`}
                  className="inline-flex items-center gap-1.5 text-xs font-bold text-purple-500 hover:text-purple-400"
                >
                  <span>Open Full Forensic Dossier</span>
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

          {/* Consistency Validation & Evidence Status Callout */}
          {validationSummary && (
            <div className="p-4 rounded-2xl border border-cyan-500/30 bg-cyan-500/5 space-y-2 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-mono text-cyan-400 font-bold uppercase tracking-wider flex items-center gap-1.5">
                  <ShieldCheck className="w-4 h-4 text-cyan-400" />
                  <span>Consistency Validation Layer Active</span>
                </span>
                <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-400 font-semibold">
                  Evidence-to-Score Integrity Verified
                </span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-2 pt-1 font-mono text-[11px]">
                <div className="p-2 rounded bg-slate-900/60 border border-slate-800">
                  <span className="text-slate-400 block text-[10px]">Explicit Secret Request:</span>
                  <span className="font-bold text-slate-200">{validationSummary.evidence_checks?.explicit_secret_demand}</span>
                </div>
                <div className="p-2 rounded bg-slate-900/60 border border-slate-800">
                  <span className="text-slate-400 block text-[10px]">Credential Verification:</span>
                  <span className="font-bold text-amber-400">{validationSummary.evidence_checks?.credential_verification_attempt}</span>
                </div>
                <div className="p-2 rounded bg-slate-900/60 border border-slate-800">
                  <span className="text-slate-400 block text-[10px]">Harvesting Intent:</span>
                  <span className="font-bold text-rose-400">{validationSummary.evidence_checks?.potential_credential_harvesting}</span>
                </div>
                <div className="p-2 rounded bg-slate-900/60 border border-slate-800">
                  <span className="text-slate-400 block text-[10px]">Embedded URL Threat:</span>
                  <span className="font-bold text-rose-400">{validationSummary.evidence_checks?.embedded_url_risk}</span>
                </div>
              </div>
            </div>
          )}

          {/* Embedded URL Analysis Section */}
          {embeddedUrls.length > 0 && (
            <div className="cyber-card p-6 rounded-2xl space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-slate-200 dark:border-slate-800">
                <div className="flex items-center gap-2">
                  <Globe className="w-4 h-4 text-cyan-500" />
                  <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase font-mono tracking-wider">
                    Embedded Link Deep Inspection ({embeddedUrls.length})
                  </h3>
                </div>
                <span className="text-xs font-mono text-slate-500">Autonomous Recursive Scans</span>
              </div>

              <div className="space-y-3">
                {embeddedUrls.map((eu: any, idx: number) => {
                  const isHigh = eu.risk_score >= 70 || eu.is_private_ip;
                  return (
                    <div
                      key={idx}
                      className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-cyber-850 space-y-3 text-xs"
                    >
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div className="flex items-center gap-2 min-w-0">
                          <span className="font-mono font-bold text-slate-900 dark:text-white truncate">
                            {eu.url}
                          </span>
                        </div>
                        <div className="flex items-center gap-2 flex-shrink-0">
                          <span className={`px-2 py-0.5 rounded font-mono font-bold text-[11px] ${
                            isHigh ? "bg-rose-500/15 text-rose-500 border border-rose-500/30" : "bg-amber-500/15 text-amber-500 border border-amber-500/30"
                          }`}>
                            Score: {eu.risk_score}/100 • {eu.risk_level}
                          </span>
                        </div>
                      </div>

                      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-2 pt-1 font-mono text-[11px]">
                        <div className="p-2 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                          <span className="text-slate-400 block text-[10px]">Host Classification:</span>
                          <span className={`font-bold ${eu.is_private_ip ? "text-rose-500" : "text-slate-200"}`}>
                            {eu.ip_classification}
                          </span>
                        </div>
                        <div className="p-2 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                          <span className="text-slate-400 block text-[10px]">Protocol Security:</span>
                          <span className="font-bold text-slate-200 flex items-center gap-1">
                            {eu.is_https ? (
                              <Lock className="w-3 h-3 text-emerald-500" />
                            ) : (
                              <Unlock className="w-3 h-3 text-amber-500" />
                            )}
                            <span>{eu.protocol} ({eu.is_https ? "Encrypted" : "Insecure"})</span>
                          </span>
                        </div>
                        <div className="p-2 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                          <span className="text-slate-400 block text-[10px]">VirusTotal Ratio:</span>
                          <span className="font-bold text-slate-200">
                            {eu.threat_intelligence?.virustotal?.malicious !== undefined
                              ? `${eu.threat_intelligence.virustotal.malicious}/${eu.threat_intelligence.virustotal.total_vendors || 60} Flagged`
                              : "Clean / Unavailable"}
                          </span>
                        </div>
                        <div className="p-2 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                          <span className="text-slate-400 block text-[10px]">Google Safe Browsing:</span>
                          <span className="font-bold text-slate-200">
                            {eu.threat_intelligence?.google_safe_browsing?.is_threat_found ? "Flagged Threat" : "No Match"}
                          </span>
                        </div>
                      </div>

                      {eu.findings && eu.findings.length > 0 && (
                        <div className="flex flex-wrap gap-1.5 pt-1">
                          {eu.findings.map((f: string, fi: number) => (
                            <span key={fi} className="px-2 py-0.5 rounded bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300 font-mono text-[10px]">
                              {f}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Email Header & Authentication Forensics (if headers provided) */}
          {headerAnalysis && headerAnalysis.has_headers && (
            <div className="cyber-card p-6 rounded-2xl space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-slate-200 dark:border-slate-800">
                <div className="flex items-center gap-2">
                  <Mail className="w-4 h-4 text-purple-500" />
                  <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase font-mono tracking-wider">
                    Email Header &amp; Authentication Analysis
                  </h3>
                </div>
                <span className="text-xs font-mono text-slate-500">Sender Verification</span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
                <div className="p-3 rounded-xl bg-slate-50 dark:bg-cyber-850 border border-slate-200 dark:border-slate-800">
                  <span className="text-slate-400 text-[10px] font-mono block">Sender (From):</span>
                  <span className="font-bold text-slate-900 dark:text-white font-mono break-all">
                    {headerAnalysis.sender_email || "Not specified"}
                  </span>
                </div>

                <div className="p-3 rounded-xl bg-slate-50 dark:bg-cyber-850 border border-slate-200 dark:border-slate-800">
                  <span className="text-slate-400 text-[10px] font-mono block">Reply-To Address:</span>
                  <span className={`font-bold font-mono break-all ${headerAnalysis.reply_to_mismatch ? "text-rose-500" : "text-slate-900 dark:text-white"}`}>
                    {headerAnalysis.reply_to_email || "Matches From"}
                    {headerAnalysis.reply_to_mismatch && " (Mismatch!)"}
                  </span>
                </div>

                <div className="p-3 rounded-xl bg-slate-50 dark:bg-cyber-850 border border-slate-200 dark:border-slate-800">
                  <span className="text-slate-400 text-[10px] font-mono block">SPF Authentication:</span>
                  <span className={`font-bold font-mono ${headerAnalysis.spf_status === "pass" ? "text-emerald-500" : (headerAnalysis.spf_status === "fail" ? "text-rose-500" : "text-slate-400")}`}>
                    {headerAnalysis.spf_status}
                  </span>
                </div>

                <div className="p-3 rounded-xl bg-slate-50 dark:bg-cyber-850 border border-slate-200 dark:border-slate-800">
                  <span className="text-slate-400 text-[10px] font-mono block">DKIM / DMARC:</span>
                  <span className="font-bold font-mono text-slate-400">
                    DKIM: {headerAnalysis.dkim_status} • DMARC: {headerAnalysis.dmarc_status}
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* Risk Score Calculation Audit Table */}
          {calculationItems.length > 0 && (
            <div className="cyber-card p-6 rounded-2xl space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-200 dark:border-slate-800">
                <div className="flex items-center gap-2">
                  <Hash className="w-4 h-4 text-purple-500" />
                  <h3 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-900 dark:text-white">
                    Risk Score Calculation Breakdown (How {scanResult.risk_score}/100 was calculated)
                  </h3>
                </div>
                <span className="text-xs font-mono font-bold px-2.5 py-0.5 rounded bg-purple-500/10 text-purple-500 border border-purple-500/30">
                  Formula: Phishing Threat Compounding
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
                    {calculationItems.map((item: any, idx: number) => (
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
                        Calculated Final Risk Score
                      </td>
                      <td className="py-2.5 px-3 text-purple-500">
                        {scanResult.risk_score} / 100
                      </td>
                      <td className="py-2.5 px-3 text-slate-500 dark:text-slate-400 font-sans">
                        Classified as {scanResult.risk_level} risk tier
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Interactive Evidence Highlighter Section */}
          <div className="cyber-card p-6 rounded-2xl space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase font-mono tracking-wider">
                  Interactive Evidence Highlighter
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  Highlighted sentences represent detected coercive, fraudulent, or manipulative language patterns.
                </p>
              </div>
            </div>

            <SentenceHighlighter
              content={content}
              flaggedSentences={scanResult.ai_analysis?.highlighted_sentences || []}
            />
          </div>

          {/* Indicators & Recommendations */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            
            {/* Indicators */}
            <div className="cyber-card p-5 rounded-2xl space-y-3">
              <h4 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                <ShieldAlert className="w-4 h-4 text-rose-500" />
                <span>Forensic Warning Signals ({scanResult.indicators?.length || 0})</span>
              </h4>
              <div className="space-y-2">
                {scanResult.indicators && scanResult.indicators.length > 0 ? (
                  scanResult.indicators.map((ind, i) => (
                    <div key={i} className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-cyber-850 text-xs">
                      <div className="flex justify-between items-center mb-1">
                        <span className="font-bold text-slate-900 dark:text-slate-100">{ind.name}</span>
                        <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-rose-500/10 text-rose-500 font-bold">
                          {ind.severity}
                        </span>
                      </div>
                      <p className="text-slate-500 dark:text-slate-400">{ind.evidence}</p>
                    </div>
                  ))
                ) : (
                  <p className="text-xs text-slate-500 py-3">No suspicious indicators triggered.</p>
                )}
              </div>
            </div>

            {/* Recommendations */}
            <div className="cyber-card p-5 rounded-2xl space-y-3">
              <h4 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                <ShieldCheck className="w-4 h-4 text-emerald-500" />
                <span>Recommended Defensive Actions</span>
              </h4>
              <ul className="space-y-2 text-xs">
                {scanResult.recommendations?.map((rec, i) => (
                  <li key={i} className="flex items-start gap-2 p-2.5 rounded-lg bg-slate-50 dark:bg-cyber-850 border border-slate-200 dark:border-slate-800">
                    <span className="w-1.5 h-1.5 rounded-full bg-purple-500 mt-1.5 flex-shrink-0" />
                    <span className="text-slate-700 dark:text-slate-300 font-medium leading-relaxed">{rec}</span>
                  </li>
                ))}
              </ul>
            </div>

          </div>

        </div>
      )}

    </div>
  );
}

export default function MessageScannerPage() {
  return (
    <Suspense fallback={<div className="p-10 text-center font-mono text-purple-500">Loading Message Scanner...</div>}>
      <MessageScannerContent />
    </Suspense>
  );
}
