import React from "react";
import Link from "next/link";
import { Lock, Activity } from "lucide-react";
import Logo from "@/components/Logo";

export default function Footer() {
  return (
    <footer className="border-t border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-cyber-950 text-slate-600 dark:text-slate-400 text-sm transition-colors">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          
          {/* Brand info */}
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <Logo size={28} showText={true} />
            </div>
            <p className="text-xs text-slate-500 leading-relaxed">
              Detect Scams. Verify Claims. Stay Protected. Unified intelligence platform combining threat intelligence, heuristic detection, and AI contextual forensics.
            </p>
          </div>

          {/* Quick Nav */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-slate-200 font-mono">
              Security Analyzers
            </h4>
            <ul className="space-y-2 text-xs">
              <li>
                <Link href="/scan/url" prefetch={true} className="hover:text-cyan-500 transition-colors">
                  URL & Domain Scanner
                </Link>
              </li>
              <li>
                <Link href="/scan/message" prefetch={true} className="hover:text-cyan-500 transition-colors">
                  Email & SMS Forensics
                </Link>
              </li>
              <li>
                <Link href="/scan/job" prefetch={true} className="hover:text-cyan-500 transition-colors">
                  Fake Job & Offer Verifier
                </Link>
              </li>
              <li>
                <Link href="/dashboard" prefetch={true} className="hover:text-cyan-500 transition-colors">
                  Threat Operations Dashboard
                </Link>
              </li>
            </ul>
          </div>

          {/* Verification Advisory */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-slate-200 font-mono">
              Operational Advisory
            </h4>
            <p className="text-xs text-slate-500 leading-relaxed">
              ScamShield AI utilizes heuristic algorithms and threat intelligence feeds. Threat confirmed is distinct from heuristic risk. Always independently verify financial transactions through official channels.
            </p>
          </div>

        </div>

        {/* Bottom Bar */}
        <div className="mt-8 pt-6 border-t border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row items-center justify-between text-xs text-slate-500 gap-4">
          <div>
            &copy; {new Date().getFullYear()} ScamShield AI Security Research. All rights reserved.
          </div>
          <div className="flex items-center space-x-6">
            <Link href="/" prefetch={true} className="hover:text-cyan-500 transition-colors">
              Terms of Service
            </Link>
            <Link href="/" prefetch={true} className="hover:text-cyan-500 transition-colors">
              Privacy Protocol
            </Link>
          </div>
        </div>
      </div>
    </footer>
  );
}
