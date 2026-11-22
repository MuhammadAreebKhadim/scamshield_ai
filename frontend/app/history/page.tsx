"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { 
  History, 
  Search, 
  Filter, 
  ExternalLink, 
  Globe, 
  MessageSquareWarning, 
  Briefcase, 
  RefreshCw,
  ShieldAlert
} from "lucide-react";
import { api, ScanRecord } from "@/lib/api";

export default function HistoryPage() {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [typeFilter, setTypeFilter] = useState("");
  const [riskFilter, setRiskFilter] = useState("");
  const [searchQuery, setSearchQuery] = useState("");

  const [currentUser, setCurrentUser] = useState<any>(null);

  const fetchHistory = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getHistory({
        type: typeFilter || undefined,
        risk_level: riskFilter || undefined,
        limit: 100,
      });
      setScans(data);
    } catch (err: any) {
      setError(err.message || "Failed to load audit history");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const checkAuth = () => {
      const savedUser = localStorage.getItem("scamshield_user");
      if (savedUser) {
        try {
          setCurrentUser(JSON.parse(savedUser));
        } catch {
          setCurrentUser(null);
        }
      } else {
        setCurrentUser(null);
      }
      fetchHistory();
    };

    checkAuth();
    window.addEventListener("auth_change", checkAuth);
    return () => {
      window.removeEventListener("auth_change", checkAuth);
    };
  }, [typeFilter, riskFilter]);

  const filteredScans = scans.filter((s) => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      s.scan_id.toLowerCase().includes(q) ||
      s.input_summary.toLowerCase().includes(q) ||
      (s.ai_analysis?.category || "").toLowerCase().includes(q)
    );
  });

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-200 dark:border-slate-800">
        <div>
          <span className="text-xs font-mono font-bold uppercase tracking-widest text-cyan-500">
            AUDIT LOG TELEMETRY
          </span>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 dark:text-white mt-1">
            Historical Scan Registry
          </h1>
          <p className="text-xs sm:text-sm text-slate-500 mt-0.5">
            Archive of all analyzed links, communications, and company verifications.
          </p>
        </div>

        <button
          onClick={fetchHistory}
          disabled={loading}
          className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-cyber-900 text-xs font-semibold hover:border-cyan-500 transition-colors self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin text-cyan-500" : ""}`} />
          <span>Refresh Records</span>
        </button>
      </div>

      {/* User Session Status Banner */}
      {currentUser ? (
        <div className="mt-4 p-3.5 rounded-xl border border-cyan-500/30 bg-cyan-500/10 text-xs font-mono text-cyan-500 dark:text-cyan-400 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
            <span>Audit Records for: <strong>{currentUser.email}</strong></span>
          </div>
          <span className="text-[11px] text-slate-500 dark:text-slate-400 hidden sm:inline">
            Directly queried from SQLite database
          </span>
        </div>
      ) : (
        <div className="mt-4 p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-100 dark:bg-cyber-900 text-xs text-slate-700 dark:text-slate-300 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div>
            <span className="font-bold text-slate-900 dark:text-white block">Guest Session (Signed Out)</span>
            <span className="text-slate-500 text-[11px]">
              Past scan histories remain securely saved in the database. Sign in with your account to access your full audit log.
            </span>
          </div>
          <Link href="/login" prefetch={true} className="px-3.5 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs whitespace-nowrap">
            Sign In with Google
          </Link>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="mt-6 flex flex-col md:flex-row items-stretch md:items-center justify-between gap-4">
        
        {/* Search */}
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filter by scan ID, target domain, or keywords..."
            className="w-full pl-9 pr-4 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-cyber-900 text-xs text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:border-cyan-500"
          />
        </div>

        {/* Filter Dropdowns */}
        <div className="flex flex-wrap items-center gap-3">
          
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="px-3 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-cyber-900 text-xs font-mono text-slate-700 dark:text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Channels</option>
            <option value="url">URLs & Domains</option>
            <option value="message">Messages & Emails</option>
            <option value="job">Job Offers</option>
          </select>

          <select
            value={riskFilter}
            onChange={(e) => setRiskFilter(e.target.value)}
            className="px-3 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-cyber-900 text-xs font-mono text-slate-700 dark:text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Risk Tiers</option>
            <option value="HIGH">High Risk</option>
            <option value="SUSPICIOUS">Suspicious</option>
            <option value="CAUTION">Caution</option>
            <option value="LOW">Low Risk</option>
          </select>

        </div>

      </div>

      {/* Table */}
      <div className="mt-6 cyber-card rounded-2xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-50 dark:bg-cyber-900 border-b border-slate-200 dark:border-slate-800 text-slate-500 uppercase tracking-wider">
              <tr>
                <th className="py-3 px-6">Scan ID</th>
                <th className="py-3 px-6">Channel</th>
                <th className="py-3 px-6">Summary / Target</th>
                <th className="py-3 px-6">Score</th>
                <th className="py-3 px-6">Verdict</th>
                <th className="py-3 px-6">Date</th>
                <th className="py-3 px-6 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
              {filteredScans.length > 0 ? (
                filteredScans.map((scan) => {
                  const isHigh = scan.risk_level === "HIGH";
                  const isSuspicious = scan.risk_level === "SUSPICIOUS";
                  const isCaution = scan.risk_level === "CAUTION";

                  const badgeColor = isHigh
                    ? "bg-rose-500/15 text-rose-500 border-rose-500/30"
                    : isSuspicious
                    ? "bg-orange-500/15 text-orange-500 border-orange-500/30"
                    : isCaution
                    ? "bg-amber-500/15 text-amber-500 border-amber-500/30"
                    : "bg-emerald-500/15 text-emerald-500 border-emerald-500/30";

                  const TypeIcon = scan.input_type === "url" 
                    ? Globe 
                    : scan.input_type === "job" 
                    ? Briefcase 
                    : MessageSquareWarning;

                  return (
                    <tr key={scan.scan_id} className="hover:bg-slate-50 dark:hover:bg-cyber-850/50 transition-colors">
                      <td className="py-4 px-6 font-bold text-cyan-600 dark:text-cyan-400">
                        {scan.scan_id}
                      </td>
                      <td className="py-4 px-6">
                        <span className="flex items-center gap-1.5 uppercase text-slate-700 dark:text-slate-300">
                          <TypeIcon className="w-3.5 h-3.5 text-slate-400" />
                          <span>{scan.input_type}</span>
                        </span>
                      </td>
                      <td className="py-4 px-6 font-sans text-slate-900 dark:text-slate-200 max-w-sm truncate">
                        {scan.input_summary}
                      </td>
                      <td className="py-4 px-6 font-bold">
                        <span className={isHigh ? "text-rose-500" : isSuspicious ? "text-orange-500" : isCaution ? "text-amber-500" : "text-emerald-500"}>
                          {scan.risk_score}/100
                        </span>
                      </td>
                      <td className="py-4 px-6">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase tracking-wider ${badgeColor}`}>
                          {scan.risk_level}
                        </span>
                      </td>
                      <td className="py-4 px-6 text-slate-500 text-[11px]">
                        {scan.created_at ? scan.created_at.split("T")[0] : "Recent"}
                      </td>
                      <td className="py-4 px-6 text-right">
                        <Link
                          href={`/report/${scan.scan_id}`}
                          className="inline-flex items-center gap-1 text-cyan-500 hover:text-cyan-400 font-semibold"
                        >
                          <span>Dossier</span>
                          <ExternalLink className="w-3 h-3" />
                        </Link>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-500 font-sans">
                    {loading ? "Loading audit trail..." : "No scan records match the current filters."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
}
