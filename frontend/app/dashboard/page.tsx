"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { 
  ShieldCheck, 
  ShieldAlert, 
  ShieldX, 
  AlertTriangle, 
  Activity, 
  RefreshCw, 
  ExternalLink, 
  Globe, 
  MessageSquareWarning, 
  Briefcase,
  Layers,
  ArrowUpRight
} from "lucide-react";
import { api, DashboardStats } from "@/lib/api";

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [currentUser, setCurrentUser] = useState<any>(null);

  const fetchStats = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getDashboardStats();
      setStats(data);
    } catch (err: any) {
      setError(err.message || "Failed to load dashboard metrics");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const checkAuthAndFetch = () => {
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
      fetchStats();
    };

    checkAuthAndFetch();
    window.addEventListener("auth_change", checkAuthAndFetch);
    return () => {
      window.removeEventListener("auth_change", checkAuthAndFetch);
    };
  }, []);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
      
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-8 border-b border-slate-200 dark:border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-500 animate-pulse"></span>
            <span className="text-xs font-mono font-bold tracking-widest uppercase text-cyan-500">
              SECURITY OPERATIONS CENTER
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 dark:text-white mt-1">
            Threat Intelligence & Scan Dashboard
          </h1>
          <p className="text-xs sm:text-sm text-slate-500 mt-1">
            Live telemetry and historical detection statistics across URLs, messages, and recruitment offers.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchStats}
            disabled={loading}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-cyber-900 text-xs font-semibold hover:border-cyan-500 transition-colors cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin text-cyan-500" : ""}`} />
            <span>Refresh Telemetry</span>
          </button>
          <Link
            href="/scan/url"
            prefetch={true}
            className="cyber-btn flex items-center gap-1.5 px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 text-white text-xs font-bold shadow-md shadow-cyan-500/20"
          >
            <span>New Scan</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </Link>
        </div>
      </div>

      {/* User Session Status Banner */}
      {currentUser ? (
        <div className="mt-6 p-3.5 rounded-xl border border-cyan-500/30 bg-cyan-500/10 text-xs font-mono text-cyan-500 dark:text-cyan-400 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
            <span>Authenticated Session: <strong>{currentUser.email}</strong></span>
          </div>
          <span className="text-[11px] text-slate-500 dark:text-slate-400 hidden sm:inline">
            Telemetry isolated to your database account
          </span>
        </div>
      ) : (
        <div className="mt-6 p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-100 dark:bg-cyber-900 text-xs text-slate-700 dark:text-slate-300 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div>
            <span className="font-bold text-slate-900 dark:text-white block">Guest Session (Signed Out)</span>
            <span className="text-slate-500 text-[11px]">
              Past scan histories remain safely stored in the database. Sign in with your account to view your previous tests and telemetry.
            </span>
          </div>
          <Link href="/login" prefetch={true} className="px-3.5 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs whitespace-nowrap">
            Sign In with Google
          </Link>
        </div>
      )}

      {error && (
        <div className="mt-6 p-4 rounded-xl border border-rose-500/30 bg-rose-500/10 text-rose-500 text-xs font-mono">
          Telemetry Error: {error}
        </div>
      )}

      {/* Metrics Cards Grid */}
      <div className="mt-8 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        
        {/* Metric 1: Total Scans */}
        <div className="cyber-card p-5 rounded-2xl">
          <div className="flex items-center justify-between text-slate-500 mb-2">
            <span className="text-xs font-mono uppercase tracking-wider font-semibold">Total Scans</span>
            <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-500">
              <Activity className="w-4 h-4" />
            </div>
          </div>
          <div className="text-3xl font-extrabold font-mono text-slate-900 dark:text-white">
            {stats?.total_scans ?? 0}
          </div>
          <span className="text-[11px] text-slate-500 mt-1 block">
            Across URL, Email & Job channels
          </span>
        </div>

        {/* Metric 2: High Risk Detections */}
        <div className="cyber-card p-5 rounded-2xl border-rose-500/20">
          <div className="flex items-center justify-between text-slate-500 mb-2">
            <span className="text-xs font-mono uppercase tracking-wider font-semibold text-rose-500">High-Risk Detections</span>
            <div className="p-2 rounded-lg bg-rose-500/10 text-rose-500">
              <ShieldX className="w-4 h-4" />
            </div>
          </div>
          <div className="text-3xl font-extrabold font-mono text-rose-500">
            {stats?.high_risk_detections ?? 0}
          </div>
          <span className="text-[11px] text-rose-600 dark:text-rose-400 mt-1 block font-mono">
            Severe scam / phishing matches
          </span>
        </div>

        {/* Metric 3: Suspicious & Caution */}
        <div className="cyber-card p-5 rounded-2xl border-amber-500/20">
          <div className="flex items-center justify-between text-slate-500 mb-2">
            <span className="text-xs font-mono uppercase tracking-wider font-semibold text-amber-500">Suspicious / Caution</span>
            <div className="p-2 rounded-lg bg-amber-500/10 text-amber-500">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="text-3xl font-extrabold font-mono text-amber-500">
            {(stats?.suspicious_detections ?? 0) + (stats?.caution_detections ?? 0)}
          </div>
          <span className="text-[11px] text-amber-600 dark:text-amber-400 mt-1 block font-mono">
            Elevated heuristic risk signals
          </span>
        </div>

        {/* Metric 4: Safe Results */}
        <div className="cyber-card p-5 rounded-2xl border-emerald-500/20">
          <div className="flex items-center justify-between text-slate-500 mb-2">
            <span className="text-xs font-mono uppercase tracking-wider font-semibold text-emerald-500">Safe / Low-Risk</span>
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-500">
              <ShieldCheck className="w-4 h-4" />
            </div>
          </div>
          <div className="text-3xl font-extrabold font-mono text-emerald-500">
            {stats?.safe_detections ?? 0}
          </div>
          <span className="text-[11px] text-emerald-600 dark:text-emerald-400 mt-1 block font-mono">
            No malicious indicators found
          </span>
        </div>

      </div>

      {/* Threat Category Breakdown */}
      <div className="mt-8">
        <div className="cyber-card p-6 rounded-2xl">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase font-mono tracking-wider">
                Threat Category Distribution
              </h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Aggregated classification of detected fraudulent patterns
              </p>
            </div>
            <Layers className="w-5 h-5 text-cyan-500" />
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4 pt-2">
            {stats && Object.entries(stats.threat_categories).map(([category, count]) => {
              const total = stats.total_scans || 1;
              const percentage = Math.round((count / total) * 100);
              return (
                <div key={category} className="p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-cyber-850">
                  <span className="text-xs text-slate-500 truncate block font-medium">{category}</span>
                  <div className="text-2xl font-bold font-mono text-slate-900 dark:text-white mt-1">
                    {count}
                  </div>
                  <div className="w-full bg-slate-200 dark:bg-slate-800 h-1.5 rounded-full mt-2 overflow-hidden">
                    <div 
                      className="bg-cyan-500 h-full rounded-full transition-all duration-500" 
                      style={{ width: `${Math.min(percentage, 100)}%` }}
                    />
                  </div>
                  <span className="text-[10px] text-slate-400 font-mono mt-1 block">{percentage}% of total</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Recent Scans Table */}
      <div className="mt-8">
        <div className="cyber-card rounded-2xl overflow-hidden">
          <div className="p-6 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase font-mono tracking-wider">
                Recent Security Scans
              </h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Latest audits processed by ScamShield detection engines
              </p>
            </div>
            <Link
              href="/history"
              className="text-xs font-semibold text-cyan-500 hover:text-cyan-400 flex items-center gap-1"
            >
              <span>View Full History</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 dark:bg-cyber-900/80 border-b border-slate-200 dark:border-slate-800 font-mono text-slate-500 uppercase tracking-wider">
                <tr>
                  <th className="py-3 px-6">Scan ID</th>
                  <th className="py-3 px-6">Channel / Type</th>
                  <th className="py-3 px-6">Input Target</th>
                  <th className="py-3 px-6">Risk Score</th>
                  <th className="py-3 px-6">Classification</th>
                  <th className="py-3 px-6">Timestamp</th>
                  <th className="py-3 px-6 text-right">Report</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800 font-mono">
                {stats?.recent_scans && stats.recent_scans.length > 0 ? (
                  stats.recent_scans.map((scan) => {
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
                        <td className="py-4 px-6 font-sans text-slate-900 dark:text-slate-200 max-w-xs truncate">
                          {scan.input_summary}
                        </td>
                        <td className="py-4 px-6 font-bold">
                          <span className={isHigh ? "text-rose-500" : isSuspicious ? "text-orange-500" : isCaution ? "text-amber-500" : "text-emerald-500"}>
                            {scan.risk_score}/100
                          </span>
                        </td>
                        <td className="py-4 px-6">
                          <span className={`px-2.5 py-1 rounded-full text-[10px] font-bold border uppercase tracking-wider ${badgeColor}`}>
                            {scan.risk_level}
                          </span>
                        </td>
                        <td className="py-4 px-6 text-slate-500 text-[11px]">
                          {scan.created_at ? scan.created_at.split("T")[0] : "Today"}
                        </td>
                        <td className="py-4 px-6 text-right">
                          <Link
                            href={`/report/${scan.scan_id}`}
                            className="inline-flex items-center gap-1 text-cyan-500 hover:text-cyan-400 font-semibold"
                          >
                            <span>Inspect</span>
                            <ExternalLink className="w-3 h-3" />
                          </Link>
                        </td>
                      </tr>
                    );
                  })
                ) : (
                  <tr>
                    <td colSpan={7} className="py-8 text-center text-slate-500 font-sans">
                      No scan records found. Run a new scan to populate telemetry.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

    </div>
  );
}
