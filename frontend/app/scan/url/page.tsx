"use client";

import React, { useState, useEffect, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { 
  Globe, 
  ShieldAlert, 
  ShieldCheck, 
  Activity, 
  ExternalLink,
  Lock,
  Unlock,
  Link2,
  CheckCircle2,
  AlertTriangle,
  Server,
  Layers,
  HelpCircle,
  Hash
} from "lucide-react";
import ThreatIntelMatrix from "@/components/ThreatIntelMatrix";
import RiskGauge from "@/components/RiskGauge";
import { api, ScanRecord } from "@/lib/api";

function URLScannerContent() {
  const searchParams = useSearchParams();
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [scanResult, setScanResult] = useState<ScanRecord | null>(null);
  const [error, setError] = useState<string | null>(null);

  function cleanInputUrl(input: string): string {
    let s = (input || "").trim();
    const mdMatch = s.match(/\[.*?\]\((https?:\/\/[^\s\)]+)\)/i);
    if (mdMatch) {
      s = mdMatch[1];
    } else {
      s = s.replace(/^[\[\(<'\"]+/, "").replace(/[\]\)>'\"]+$/, "").trim();
    }
    return s;
  }

  useEffect(() => {
    const rawTarget = searchParams.get("url") || searchParams.get("target");
    if (rawTarget) {
      const cleaned = cleanInputUrl(rawTarget);
      setUrl(cleaned);
      handleScan(cleaned);
    }
  }, [searchParams]);

  const handleScan = async (targetUrl: string) => {
    const cleanUrl = cleanInputUrl(targetUrl);
    if (!cleanUrl) return;

    setLoading(true);
    setError(null);
    try {
      const result = await api.scanURL(cleanUrl);
      setScanResult(result);
    } catch (err: any) {
      setError(err.message || "Failed to analyze URL");
    } finally {
      setLoading(false);
    }
  };

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    handleScan(url);
  };

  const calculationDetails = scanResult?.score_breakdown?.calculation_items || [];
  const ipCheck = scanResult?.input_data?.ip_check;
  const domainAge = scanResult?.input_data?.domain_age;
  const brandCheck = scanResult?.input_data?.brand_check;
  const keywords = scanResult?.input_data?.keywords;
  const shortener = scanResult?.input_data?.shortener;
  const punycode = scanResult?.input_data?.punycode;
  const dnsRecords = scanResult?.input_data?.dns_records;
  const redirects = scanResult?.input_data?.redirects;
  const protocolAnalysis = scanResult?.input_data?.protocol_analysis;

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
      
      {/* Title Header */}
      <div className="text-center max-w-2xl mx-auto space-y-3 mb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-cyan-500/30 bg-cyan-500/10 text-cyan-500 text-xs font-mono font-semibold">
          <Globe className="w-3.5 h-3.5" />
          <span>REAL-TIME URL & DOMAIN THREAT INTELLIGENCE</span>
        </div>
        <h1 className="text-3xl font-extrabold text-slate-900 dark:text-white">
          URL Security Scanner
        </h1>
        <p className="text-xs sm:text-sm text-slate-500">
          Deconstructs URL architecture, queries URLhaus, VirusTotal & Google Safe Browsing, checks Punycode, redirect chains, DNS resolution, and validates domain age via RDAP.
        </p>
      </div>

      {/* Input Form with generous padding and separated responsive button (no overlapping) */}
      <div className="cyber-card p-5 sm:p-6 rounded-2xl shadow-xl mb-8">
        <form onSubmit={onSubmit}>
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
            <div className="relative flex-1 flex items-center">
              <Globe className="w-5 h-5 text-slate-400 absolute left-4 flex-shrink-0" />
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="Enter suspicious link or IP (e.g. http://192.168.1.100/login or https://paypal.com.verify-access.net)"
                className="w-full pl-12 pr-4 py-3.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-cyber-900 text-sm font-mono text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:border-cyan-500 transition-colors"
              />
            </div>
            <button
              type="submit"
              disabled={loading || !url.trim()}
              className="cyber-btn px-7 py-3.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-semibold text-sm shadow-md shadow-cyan-500/25 disabled:opacity-50 flex items-center justify-center gap-2 whitespace-nowrap cursor-pointer transition-all"
            >
              {loading ? (
                <span className="flex items-center gap-2 font-mono">
                  <Activity className="w-4 h-4 animate-spin" /> Scanning...
                </span>
              ) : (
                <span>Analyze URL</span>
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

      {/* Scanning Animation Progress */}
      {loading && (
        <div className="cyber-card p-8 rounded-2xl text-center space-y-4 mb-8">
          <div className="w-12 h-12 rounded-full border-4 border-cyan-500/20 border-t-cyan-500 animate-spin mx-auto" />
          <div className="space-y-1">
            <p className="font-mono text-sm font-bold text-slate-900 dark:text-white">
              Deconstructing URL Architecture &amp; Querying Intelligence Feeds...
            </p>
            <p className="text-xs text-slate-500 font-mono">
              Probing URLhaus, VirusTotal v3, Google Safe Browsing, DNS records &amp; RDAP authority
            </p>
          </div>
        </div>
      )}

      {/* Full Scan Results Presentation */}
      {scanResult && !loading && (
        <div className="space-y-8 animate-fadeIn">
          
          {/* Top Summary Dossier Card */}
          <div className="cyber-card p-6 sm:p-8 rounded-2xl flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="space-y-3 flex-1 text-left">
              <div className="flex items-center gap-3">
                <span className="text-[11px] font-mono text-cyan-500 font-bold uppercase tracking-wider">
                  SCAN ID: {scanResult.scan_id}
                </span>
                <span className="text-xs text-slate-400 font-mono">
                  {scanResult.created_at ? scanResult.created_at.split("T")[0] : "Today"}
                </span>
              </div>
              <h2 className="text-xl font-bold text-slate-900 dark:text-white font-mono break-all">
                {scanResult.input_summary}
              </h2>
              <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                {scanResult.ai_analysis?.summary || "Analysis completed across threat feeds and local heuristic engines."}
              </p>
              <div className="pt-2">
                <Link
                  href={`/report/${scanResult.scan_id}`}
                  className="inline-flex items-center gap-1.5 text-xs font-bold text-cyan-500 hover:text-cyan-400"
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

          {/* Risk Score Calculation & Weight Breakdown */}
          <div className="cyber-card p-5 sm:p-6 rounded-2xl space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-200 dark:border-slate-800">
              <div className="flex items-center gap-2">
                <Hash className="w-4 h-4 text-cyan-500" />
                <h3 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-900 dark:text-white">
                  Risk Score Calculation Breakdown (How {scanResult.risk_score}/100 was calculated)
                </h3>
              </div>
              <span className="text-xs font-mono font-bold px-2.5 py-0.5 rounded bg-cyan-500/10 text-cyan-500 border border-cyan-500/30">
                Formula: Weighted Multi-Engine Signals
              </span>
            </div>

            {calculationDetails.length > 0 ? (
              <div className="space-y-2">
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-400 font-mono text-[11px] uppercase">
                        <th className="py-2 px-3">Evaluated Signal</th>
                        <th className="py-2 px-3">Point Contribution</th>
                        <th className="py-2 px-3">Technical Evidence / Reasoning</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60 font-mono">
                      {calculationDetails.map((item: any, idx: number) => (
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
                          {scanResult.risk_score} / 100
                        </td>
                        <td className="py-2.5 px-3 text-slate-500 dark:text-slate-400 font-sans">
                          Classified as {scanResult.risk_level} risk tier (Signals deduplicated to prevent artificial score inflation)
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>
            ) : (
              <div className="p-3 text-xs text-slate-500">
                Score: {scanResult.risk_score}/100 based on verified zero-threat signals.
              </div>
            )}
          </div>

          {/* External Threat Intelligence Layer */}
          <div>
            <h3 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-500 mb-3">
              External Threat Intelligence Results
            </h3>
            <ThreatIntelMatrix threatIntel={scanResult.threat_intelligence} />
          </div>

          {/* Enhanced Structural & Heuristic Indicators Grid */}
          <div>
            <h3 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-500 mb-3">
              Structural &amp; Heuristic Indicators
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              
              {/* 1. Domain Age (Never displays "Established domain" when data unavailable) */}
              <div className="cyber-card p-4 rounded-xl text-xs space-y-1">
                <span className="text-slate-400 font-mono text-[11px] block">Domain Age</span>
                <span className="font-bold text-slate-900 dark:text-white font-mono text-sm block">
                  {domainAge?.age_days !== undefined && domainAge?.age_days !== null
                    ? `${domainAge.age_days} Days`
                    : "Unavailable"}
                </span>
                <span className="text-[11px] text-slate-500 leading-tight block">
                  {domainAge?.age_days !== undefined && domainAge?.age_days !== null
                    ? (domainAge.is_new ? "Recently registered (<30d)" : `Established domain (${domainAge.age_days}d)`)
                    : (ipCheck?.is_ip ? "N/A — Direct IP Host" : "Unavailable — Registration data not retrieved.")}
                </span>
              </div>

              {/* 2. Direct IP Host (Explicitly identifies Private vs Public IP) */}
              <div className="cyber-card p-4 rounded-xl text-xs space-y-1">
                <span className="text-slate-400 font-mono text-[11px] block">Direct IP Host</span>
                <span className="font-bold text-slate-900 dark:text-white font-mono text-sm block">
                  {ipCheck?.is_ip 
                    ? (ipCheck.is_private ? "Yes (Private IP)" : "Yes (Public IP)")
                    : "No (Domain)"}
                </span>
                <span className="text-[11px] text-slate-500 block truncate">
                  {ipCheck?.is_ip
                    ? (ipCheck.is_private ? "Private • RFC 1918 / LAN" : "Public • Direct Host")
                    : "Domain Host"}
                </span>
              </div>

              {/* 3. HTTPS / Protocol Status (Separate visibility) */}
              <div className="cyber-card p-4 rounded-xl text-xs space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400 font-mono text-[11px] block">Connection Protocol</span>
                  {protocolAnalysis?.is_https ? (
                    <Lock className="w-3.5 h-3.5 text-emerald-500" />
                  ) : (
                    <Unlock className="w-3.5 h-3.5 text-amber-500" />
                  )}
                </div>
                <span className="font-bold text-slate-900 dark:text-white font-mono text-sm block">
                  {protocolAnalysis?.protocol || "HTTP"} ({protocolAnalysis?.is_https ? "Encrypted" : "Insecure"})
                </span>
                <span className="text-[11px] text-slate-500 block truncate" title="HTTPS encrypts in transit but does not guarantee website legitimacy">
                  {protocolAnalysis?.is_https 
                    ? "Encrypted in transit. Does NOT guarantee authenticity." 
                    : "Cleartext HTTP. Data unencrypted in transit."}
                </span>
              </div>

              {/* 4. Brand Similarity & Typosquatting */}
              <div className="cyber-card p-4 rounded-xl text-xs space-y-1">
                <span className="text-slate-400 font-mono text-[11px] block">Brand Similarity</span>
                <span className="font-bold text-slate-900 dark:text-white font-mono text-sm block">
                  {brandCheck?.impersonation_detected
                    ? `Impersonating: ${brandCheck.impersonated_brand}`
                    : "None Detected"}
                </span>
                <span className="text-[11px] text-slate-500 truncate block">
                  {brandCheck?.impersonation_detected 
                    ? `${brandCheck.similarity_percentage}% match (${brandCheck.reason})` 
                    : "No typosquatting found"}
                </span>
              </div>

              {/* 5. URL Shortener Detection */}
              <div className="cyber-card p-4 rounded-xl text-xs space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400 font-mono text-[11px] block">URL Shortener</span>
                  <Link2 className="w-3.5 h-3.5 text-cyan-500" />
                </div>
                <span className="font-bold text-slate-900 dark:text-white font-mono text-sm block">
                  {shortener?.is_shortened ? `Detected (${shortener.service})` : "None (Direct Link)"}
                </span>
                <span className="text-[11px] text-slate-500 block truncate">
                  {shortener?.is_shortened ? "Conceals true destination" : "Standard URL destination"}
                </span>
              </div>

              {/* 6. Punycode / Homoglyph Detection */}
              <div className="cyber-card p-4 rounded-xl text-xs space-y-1">
                <span className="text-slate-400 font-mono text-[11px] block">Punycode / Homoglyphs</span>
                <span className="font-bold text-slate-900 dark:text-white font-mono text-sm block">
                  {punycode?.is_suspicious_homoglyph ? "Spoof Detected" : "Standard ASCII"}
                </span>
                <span className="text-[11px] text-slate-500 block truncate">
                  {punycode?.is_suspicious_homoglyph 
                    ? `Decodes to: ${punycode.decoded_hostname}` 
                    : "No Unicode lookalike characters"}
                </span>
              </div>

              {/* 7. DNS Resolution Check */}
              <div className="cyber-card p-4 rounded-xl text-xs space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400 font-mono text-[11px] block">DNS Resolution</span>
                  <Server className="w-3.5 h-3.5 text-blue-500" />
                </div>
                <span className="font-bold text-slate-900 dark:text-white font-mono text-sm block truncate">
                  {dnsRecords?.dns_status || "Resolved"}
                </span>
                <span className="text-[11px] text-slate-500 block truncate">
                  {dnsRecords?.resolved_ips?.length 
                    ? `${dnsRecords.resolved_ips.length} IP(s) mapped` 
                    : (ipCheck?.is_ip ? "Direct IP (DNS bypassed)" : "No active DNS mappings")}
                </span>
              </div>

              {/* 8. Redirect Analysis & Suspicious Keywords */}
              <div className="cyber-card p-4 rounded-xl text-xs space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400 font-mono text-[11px] block">Redirect Chain &amp; Words</span>
                  <Layers className="w-3.5 h-3.5 text-purple-500" />
                </div>
                <span className="font-bold text-slate-900 dark:text-white font-mono text-sm block">
                  {redirects?.has_redirects ? `${redirects.redirect_count} Redirect Hops` : "Direct Link"}
                </span>
                <span className="text-[11px] text-slate-500 block truncate">
                  {keywords?.only_auth_keyword 
                    ? "Normal auth path ('login')" 
                    : (keywords?.count ? `${keywords.count} keyword(s) detected` : "Clean path tokens")}
                </span>
              </div>

            </div>
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
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-500 mt-1.5 flex-shrink-0" />
                    <span className="text-slate-700 dark:text-slate-300 font-medium">{rec}</span>
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

export default function URLScannerPage() {
  return (
    <Suspense fallback={<div className="p-10 text-center font-mono text-cyan-500">Loading URL Scanner...</div>}>
      <URLScannerContent />
    </Suspense>
  );
}
