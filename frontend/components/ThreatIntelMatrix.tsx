import React from "react";
import { Server, Database, ShieldCheck, ShieldAlert, CheckCircle2, XCircle, AlertCircle, HelpCircle } from "lucide-react";
import { ThreatIntelligence } from "@/lib/api";

interface ThreatIntelMatrixProps {
  threatIntel?: ThreatIntelligence;
}

export default function ThreatIntelMatrix({ threatIntel }: ThreatIntelMatrixProps) {
  const urlhaus = threatIntel?.urlhaus;
  const virustotal = threatIntel?.virustotal;
  const gsb = threatIntel?.google_safe_browsing;

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      
      {/* 1. URLhaus Card */}
      <div className="cyber-card p-4 rounded-xl flex flex-col justify-between">
        <div className="flex items-center justify-between pb-3 border-b border-slate-200 dark:border-slate-800">
          <div className="flex items-center gap-2">
            <Server className="w-4 h-4 text-cyan-500" />
            <span className="font-semibold text-xs text-slate-800 dark:text-slate-200">URLhaus (abuse.ch)</span>
          </div>
          {urlhaus?.is_malicious ? (
            <span className="flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded bg-rose-500/15 border border-rose-500/30 text-rose-500 font-semibold">
              <XCircle className="w-3 h-3" /> Malicious
            </span>
          ) : urlhaus?.status === "no_match" ? (
            <span className="flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded bg-emerald-500/15 border border-emerald-500/30 text-emerald-500 font-semibold">
              <CheckCircle2 className="w-3 h-3" /> No Match
            </span>
          ) : (
            <span className="flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded bg-slate-500/15 text-slate-400 font-semibold">
              <HelpCircle className="w-3 h-3" /> {urlhaus?.status || "Unavailable"}
            </span>
          )}
        </div>

        <div className="pt-3 text-xs space-y-1.5 text-slate-600 dark:text-slate-400">
          <div className="flex justify-between">
            <span className="text-slate-500">Threat Type:</span>
            <span className="font-mono font-medium text-slate-900 dark:text-slate-200">
              {urlhaus?.threat || "None detected"}
            </span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-500">URL Status:</span>
            <span className="font-mono text-slate-700 dark:text-slate-300">
              {urlhaus?.url_status || "N/A"}
            </span>
          </div>
          {urlhaus?.tags && urlhaus.tags.length > 0 && (
            <div className="pt-1 flex flex-wrap gap-1">
              {urlhaus.tags.map((tag, i) => (
                <span key={i} className="px-1.5 py-0.5 bg-slate-200 dark:bg-slate-800 rounded font-mono text-[10px] text-cyan-600 dark:text-cyan-400">
                  {tag}
                </span>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* 2. VirusTotal Card */}
      <div className="cyber-card p-4 rounded-xl flex flex-col justify-between">
        <div className="flex items-center justify-between pb-3 border-b border-slate-200 dark:border-slate-800">
          <div className="flex items-center gap-2">
            <Database className="w-4 h-4 text-blue-500" />
            <span className="font-semibold text-xs text-slate-800 dark:text-slate-200">VirusTotal v3</span>
          </div>
          {(virustotal?.malicious ?? 0) > 0 ? (
            <span className="flex items-center gap-1.5 text-[11px] font-mono px-2.5 py-1 rounded-md bg-rose-500/15 border border-rose-500/30 text-rose-500 font-bold shadow-sm">
              <XCircle className="w-3.5 h-3.5 flex-shrink-0" />
              <span>{virustotal?.malicious}/{virustotal?.total_vendors || 60} Vendors Flagged</span>
            </span>
          ) : virustotal?.status === "success" ? (
            <span className="flex items-center gap-1.5 text-[11px] font-mono px-2.5 py-1 rounded-md bg-emerald-500/15 border border-emerald-500/30 text-emerald-500 font-bold">
              <CheckCircle2 className="w-3.5 h-3.5 flex-shrink-0" />
              <span>0/{virustotal?.total_vendors || 60} Flagged (Clean)</span>
            </span>
          ) : (
            <span className="flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded bg-slate-500/15 text-slate-400 font-semibold">
              <HelpCircle className="w-3 h-3" /> {virustotal?.status || "Unavailable"}
            </span>
          )}
        </div>

        <div className="pt-3 text-xs space-y-1.5 text-slate-600 dark:text-slate-400">
          <div className="flex justify-between">
            <span className="text-slate-500">Security Vendors:</span>
            <span className="font-mono text-slate-900 dark:text-slate-200">
              <span className="text-rose-500 font-bold">{virustotal?.malicious ?? 0}</span> Malicious / <span className="text-emerald-500">{virustotal?.harmless ?? 0}</span> Harmless
            </span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-500">Suspicious Votes:</span>
            <span className="font-mono text-amber-500">
              {virustotal?.suspicious ?? 0}
            </span>
          </div>
          <p className="text-[11px] text-slate-500 pt-1 line-clamp-1">
            {virustotal?.summary || "Aggregated antivirus vendor analysis"}
          </p>
        </div>
      </div>

      {/* 3. Google Safe Browsing Card */}
      <div className="cyber-card p-4 rounded-xl flex flex-col justify-between">
        <div className="flex items-center justify-between pb-3 border-b border-slate-200 dark:border-slate-800">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-500" />
            <span className="font-semibold text-xs text-slate-800 dark:text-slate-200">Google Safe Browsing</span>
          </div>
          {gsb?.is_threat_found ? (
            <span className="flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded bg-rose-500/15 border border-rose-500/30 text-rose-500 font-semibold">
              <AlertCircle className="w-3 h-3" /> Threat Detected
            </span>
          ) : gsb?.status === "no_match" ? (
            <span className="flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded bg-emerald-500/15 border border-emerald-500/30 text-emerald-500 font-semibold">
              <CheckCircle2 className="w-3 h-3" /> No Match
            </span>
          ) : (
            <span className="flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded bg-slate-500/15 text-slate-400 font-semibold">
              <HelpCircle className="w-3 h-3" /> {gsb?.status || "Unavailable"}
            </span>
          )}
        </div>

        <div className="pt-3 text-xs space-y-1.5 text-slate-600 dark:text-slate-400">
          <div className="flex justify-between">
            <span className="text-slate-500">Target Match:</span>
            <span className="font-mono font-medium text-slate-900 dark:text-slate-200">
              {gsb?.threat_types && gsb.threat_types.length > 0
                ? gsb.threat_types.join(", ")
                : "No matching threat"}
            </span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-500">Coverage:</span>
            <span className="font-mono text-slate-700 dark:text-slate-300">
              Phishing, Malware, Unwanted Apps
            </span>
          </div>
          <p className="text-[11px] text-slate-500 pt-1 line-clamp-1">
            {gsb?.summary || "Google verified unsafe list"}
          </p>
        </div>
      </div>

    </div>
  );
}
