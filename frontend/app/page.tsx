"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { 
  Globe, 
  MessageSquareWarning, 
  Briefcase, 
  ShieldCheck, 
  ShieldAlert, 
  Activity, 
  Search, 
  ArrowRight,
  Cpu
} from "lucide-react";

export default function HomePage() {
  const router = useRouter();
  const [quickInput, setQuickInput] = useState("");
  const [authNotice, setAuthNotice] = useState<string | null>(null);

  const handleQuickScan = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = quickInput.trim();
    if (!trimmed) return;

    // Check authentication: restrict anonymous scans from home bar and demand sign-in
    const token = typeof window !== "undefined" ? localStorage.getItem("scamshield_token") : null;
    if (!token) {
      if (typeof window !== "undefined") {
        sessionStorage.setItem("scamshield_pending_scan", trimmed);
      }
      setAuthNotice("Authentication required: Please sign in first to analyze this link or content.");
      setTimeout(() => {
        router.push("/login?notice=auth_required");
      }, 1000);
      return;
    }

    if (trimmed.startsWith("http://") || trimmed.startsWith("https://") || trimmed.includes("www.") || (trimmed.includes(".") && !trimmed.includes(" "))) {
      router.push(`/scan/url?target=${encodeURIComponent(trimmed)}`);
    } else if (trimmed.toLowerCase().includes("hiring") || trimmed.toLowerCase().includes("position") || trimmed.toLowerCase().includes("intern") || trimmed.toLowerCase().includes("salary")) {
      router.push(`/scan/job?desc=${encodeURIComponent(trimmed)}`);
    } else {
      router.push(`/scan/message?content=${encodeURIComponent(trimmed)}`);
    }
  };

  return (
    <div className="relative overflow-hidden py-8 sm:py-12 lg:py-20">
      
      {/* Background Animated Glow Elements */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[320px] sm:w-[600px] h-[250px] sm:h-[350px] bg-gradient-to-tr from-cyan-500/10 via-blue-500/10 to-indigo-500/10 rounded-full blur-3xl pointer-events-none animate-pulse-glow" />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        
        {/* Hero Section */}
        <div className="text-center max-w-4xl mx-auto space-y-5 sm:space-y-6">
          
          {/* Status Pill */}
          <div className="inline-flex items-center gap-2 px-3 sm:px-3.5 py-1 sm:py-1.5 rounded-full border border-cyan-500/30 bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 text-[11px] sm:text-xs font-mono tracking-wide">
            <Activity className="w-3.5 h-3.5 animate-spin flex-shrink-0" />
            <span className="truncate">REAL-TIME THREAT INTELLIGENCE &amp; HEURISTIC ENGINE</span>
          </div>

          {/* Main Title */}
          <h1 className="text-3xl sm:text-5xl lg:text-6xl font-extrabold tracking-tight text-slate-900 dark:text-white leading-[1.18] sm:leading-[1.15]">
            Stay One Step Ahead of <br className="hidden sm:inline" />
            <span className="bg-gradient-to-r from-cyan-500 via-blue-500 to-indigo-500 bg-clip-text text-transparent">
              Digital Scams &amp; Fraud.
            </span>
          </h1>

          {/* Subtitle */}
          <p className="text-sm sm:text-lg text-slate-600 dark:text-slate-300 max-w-2xl mx-auto leading-relaxed px-2">
            Analyze suspicious URLs, phishing emails, SMS, and fake job offers using real-time threat intelligence and AI-powered evidence forensics.
          </p>

          {/* Omni Quick-Scan Input Bar */}
          <form onSubmit={handleQuickScan} className="max-w-2xl mx-auto mt-6 sm:mt-8">
            <div className="relative flex flex-col sm:flex-row items-stretch sm:items-center p-2 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white/90 dark:bg-cyber-900/90 shadow-2xl backdrop-blur-md focus-within:border-cyan-500 transition-all gap-2 sm:gap-0">
              <div className="flex items-center flex-1 px-2">
                <Search className="w-5 h-5 text-slate-400 flex-shrink-0 ml-1" />
                <input
                  type="text"
                  value={quickInput}
                  onChange={(e) => setQuickInput(e.target.value)}
                  placeholder="Paste link, message, or job offer..."
                  className="w-full bg-transparent px-3 py-2.5 text-base sm:text-sm text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none"
                />
              </div>
              <button
                type="submit"
                className="cyber-btn flex items-center justify-center gap-2 px-6 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-semibold text-sm shadow-lg shadow-cyan-500/25 hover:brightness-110 active:scale-95 transition-all whitespace-nowrap cursor-pointer w-full sm:w-auto"
              >
                <span>Analyze Now</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
            {authNotice && (
              <div className="mt-4 p-3.5 sm:p-4 rounded-xl border border-rose-500/30 bg-rose-500/10 text-rose-600 dark:text-rose-400 text-xs sm:text-sm font-medium flex items-center justify-between gap-3 text-left animate-fadeIn">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 flex-shrink-0 text-rose-500" />
                  <span>{authNotice}</span>
                </div>
                <Link
                  href="/login?notice=auth_required"
                  className="px-3 py-1.5 rounded-lg bg-rose-500 text-white text-xs font-semibold hover:bg-rose-600 transition-colors whitespace-nowrap"
                >
                  Sign In
                </Link>
              </div>
            )}
            <div className="flex items-center justify-center gap-4 sm:gap-6 mt-3 text-[11px] sm:text-xs text-slate-500 dark:text-slate-400 font-mono">
              <span>Auto-detects: Links</span>
              <span>Messages</span>
              <span>Job Offers</span>
            </div>
          </form>

        </div>

        {/* Three Primary Action Cards */}
        <div className="mt-12 sm:mt-16 grid grid-cols-1 md:grid-cols-3 gap-4 sm:gap-6 max-w-6xl mx-auto">
          
          {/* Card 1: URL Scanner */}
          <Link
            href="/scan/url"
            prefetch={true}
            className="cyber-card p-6 rounded-2xl group flex flex-col justify-between relative overflow-hidden"
          >
            <div className="absolute top-0 right-0 w-24 h-24 bg-cyan-500/5 rounded-full blur-xl group-hover:bg-cyan-500/15 transition-all" />
            <div>
              <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-500 flex items-center justify-center mb-4 group-hover:scale-110 group-hover:bg-cyan-500 group-hover:text-white transition-all duration-300">
                <Globe className="w-6 h-6" />
              </div>
              <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-2 group-hover:text-cyan-500 transition-colors">
                URL Security Scanner
              </h3>
              <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed mb-4">
                Deconstructs suspicious links using threat intelligence feeds combined with RDAP domain age verification and brand typosquatting detection.
              </p>
            </div>
            <div className="flex items-center text-xs font-semibold text-cyan-500 group-hover:translate-x-1 transition-transform">
              <span>Launch Link Scanner</span>
              <ArrowRight className="w-4 h-4 ml-1.5" />
            </div>
          </Link>

          {/* Card 2: Message Scanner */}
          <Link
            href="/scan/message"
            prefetch={true}
            className="cyber-card p-6 rounded-2xl group flex flex-col justify-between relative overflow-hidden"
          >
            <div className="absolute top-0 right-0 w-24 h-24 bg-purple-500/5 rounded-full blur-xl group-hover:bg-purple-500/15 transition-all" />
            <div>
              <div className="w-12 h-12 rounded-xl bg-purple-500/10 border border-purple-500/30 text-purple-500 flex items-center justify-center mb-4 group-hover:scale-110 group-hover:bg-purple-500 group-hover:text-white transition-all duration-300">
                <MessageSquareWarning className="w-6 h-6" />
              </div>
              <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-2 group-hover:text-purple-500 transition-colors">
                Message & Email Scanner
              </h3>
              <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed mb-4">
                Inspects emails, SMS, WhatsApp texts, and social DMs for social engineering, financial requests, artificial urgency, and highlights exact deceptive sentences.
              </p>
            </div>
            <div className="flex items-center text-xs font-semibold text-purple-500 group-hover:translate-x-1 transition-transform">
              <span>Analyze Message</span>
              <ArrowRight className="w-4 h-4 ml-1.5" />
            </div>
          </Link>

          {/* Card 3: Job Verifier */}
          <Link
            href="/scan/job"
            prefetch={true}
            className="cyber-card p-6 rounded-2xl group flex flex-col justify-between relative overflow-hidden"
          >
            <div className="absolute top-0 right-0 w-24 h-24 bg-blue-500/5 rounded-full blur-xl group-hover:bg-blue-500/15 transition-all" />
            <div>
              <div className="w-12 h-12 rounded-xl bg-blue-500/10 border border-blue-500/30 text-blue-500 flex items-center justify-center mb-4 group-hover:scale-110 group-hover:bg-blue-500 group-hover:text-white transition-all duration-300">
                <Briefcase className="w-6 h-6" />
              </div>
              <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-2 group-hover:text-blue-500 transition-colors">
                Fake Job & Recruiter Verifier
              </h3>
              <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed mb-4">
                Validates claimed employer legitimacy across enterprise registries, flags recruiter domain mismatches, public webmail impersonation, and unmasks advance fee hiring schemes.
              </p>
            </div>
            <div className="flex items-center text-xs font-semibold text-blue-500 group-hover:translate-x-1 transition-transform">
              <span>Verify Recruitment Offer</span>
              <ArrowRight className="w-4 h-4 ml-1.5" />
            </div>
          </Link>

        </div>

        {/* Forensic Capabilities Grid */}
        <div className="mt-16 max-w-6xl mx-auto">
          <div className="text-center mb-10">
            <span className="text-xs font-mono uppercase tracking-wider text-cyan-500 font-semibold">
              Deep Heuristic Architecture
            </span>
            <h2 className="text-2xl font-bold text-slate-900 dark:text-white mt-1">
              Evidence-Based Detection, Not Black-Box Guesses
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="p-5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-cyber-900 space-y-2">
              <div className="w-8 h-8 rounded-lg bg-cyan-500/10 text-cyan-500 flex items-center justify-center">
                <Globe className="w-4 h-4" />
              </div>
              <h4 className="text-sm font-bold text-slate-900 dark:text-white">RDAP Domain Age</h4>
              <p className="text-xs text-slate-500 leading-relaxed">
                Queries the authoritative registry to calculate domain age. Domains registered in the last 30 days are automatically flagged as elevated risk.
              </p>
            </div>

            <div className="p-5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-cyber-900 space-y-2">
              <div className="w-8 h-8 rounded-lg bg-blue-500/10 text-blue-500 flex items-center justify-center">
                <ShieldAlert className="w-4 h-4" />
              </div>
              <h4 className="text-sm font-bold text-slate-900 dark:text-white">Brand Impersonation & Typos</h4>
              <p className="text-xs text-slate-500 leading-relaxed">
                Detects homoglyphs, character substitutions, Levenshtein distance typosquatting, and brand keywords embedded in unrelated registered domains.
              </p>
            </div>

            <div className="p-5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-cyber-900 space-y-2">
              <div className="w-8 h-8 rounded-lg bg-purple-500/10 text-purple-500 flex items-center justify-center">
                <Cpu className="w-4 h-4" />
              </div>
              <h4 className="text-sm font-bold text-slate-900 dark:text-white">AI Contextual Forensics</h4>
              <p className="text-xs text-slate-500 leading-relaxed">
                Analyzes text intent with neural heuristics to identify psychological manipulation, advance fee schemes, fake job traps, and highlights the exact deceptive sentences.
              </p>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
