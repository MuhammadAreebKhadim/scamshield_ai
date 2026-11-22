"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";
import { X, AlertCircle, CheckCircle2 } from "lucide-react";
import { api } from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const completeLogin = () => {
    setSuccess(true);
    if (typeof window !== "undefined") {
      window.dispatchEvent(new Event("auth_change"));
      setTimeout(() => {
        router.push("/dashboard");
      }, 350);
    }
  };

  const handleContinueWithGoogle = async () => {
    // If user provided email/name in the form, use it
    if (!email.trim()) {
      setError("Please enter your Google account email address below, or complete authorization.");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const targetEmail = email.trim();
      const targetName = name.trim() || (targetEmail.includes("@") ? targetEmail.split("@")[0] : "User");
      await api.emailAuth(targetEmail, targetName);
      completeLogin();
    } catch (err: any) {
      setError(err.message || "Failed to authenticate with Google account");
    } finally {
      setLoading(false);
    }
  };

  const handleManualSignIn = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim() || !email.includes("@")) {
      setError("Please provide a valid email address");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      await api.emailAuth(email.trim(), name.trim() || undefined);
      completeLogin();
    } catch (err: any) {
      setError(err.message || "Sign-in failed. Please verify credentials.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-[calc(100vh-140px)] flex items-center justify-center px-4 py-10 sm:py-16">
      {/* Google Account Sign-In Card matching uploaded reference design */}
      <div className="w-full max-w-[460px] bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-2xl p-7 sm:p-8 space-y-6">
        
        {/* Header: Google Icon + Title + Close Button */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-3">
              {/* Google Brand Colored 'G' Icon */}
              <svg className="w-6 h-6 flex-shrink-0" viewBox="0 0 24 24">
                <path
                  fill="#4285F4"
                  d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                />
                <path
                  fill="#34A853"
                  d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                />
                <path
                  fill="#FBBC05"
                  d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
                />
                <path
                  fill="#EA4335"
                  d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
                />
              </svg>
              <h1 className="text-xl font-bold text-slate-800 dark:text-white tracking-tight">
                Google Account Sign-In
              </h1>
            </div>

            <button
              type="button"
              onClick={() => router.push("/")}
              className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition-colors p-1 rounded-lg"
              aria-label="Close"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          <p className="text-sm text-slate-500 dark:text-slate-400 leading-relaxed">
            Sign in to access threat intelligence, link &amp; message forensics, and historical telemetry.
          </p>
        </div>

        {/* Error notification */}
        {error && (
          <div className="p-3 rounded-xl border border-rose-500/20 bg-rose-500/10 text-rose-500 text-xs flex items-center gap-2">
            <AlertCircle className="w-4 h-4 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Success notification */}
        {success && (
          <div className="p-3 rounded-xl border border-emerald-500/20 bg-emerald-500/10 text-emerald-500 text-xs flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
            <span>Authenticated successfully. Redirecting to dashboard...</span>
          </div>
        )}

        {/* Continue with Google button */}
        <button
          type="button"
          onClick={handleContinueWithGoogle}
          disabled={loading}
          className="w-full flex items-center justify-center gap-3 py-3 px-4 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800/80 hover:bg-slate-50 dark:hover:bg-slate-700/60 shadow-sm transition-all text-slate-700 dark:text-slate-200 text-sm font-medium cursor-pointer disabled:opacity-60"
        >
          <svg className="w-5 h-5 flex-shrink-0" viewBox="0 0 24 24">
            <path
              fill="#4285F4"
              d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
            />
            <path
              fill="#34A853"
              d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
            />
            <path
              fill="#FBBC05"
              d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
            />
            <path
              fill="#EA4335"
              d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
            />
          </svg>
          <span>Continue with Google</span>
        </button>

        {/* Divider: OR SIGN IN WITH NAME & EMAIL */}
        <div className="relative my-4 flex items-center justify-center">
          <div className="border-t border-slate-200 dark:border-slate-800 w-full" />
          <span className="bg-white dark:bg-slate-900 px-3 text-[11px] font-semibold tracking-wider text-slate-400 uppercase whitespace-nowrap">
            OR SIGN IN WITH NAME &amp; EMAIL
          </span>
          <div className="border-t border-slate-200 dark:border-slate-800 w-full" />
        </div>

        {/* Manual Name & Email Form */}
        <form onSubmit={handleManualSignIn} className="space-y-4 text-left">
          {/* User Name Field */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="text-sm font-semibold text-slate-800 dark:text-slate-200">
                User Name
              </label>
              <span className="text-xs text-slate-400">Required</span>
            </div>
            <input
              type="text"
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Enter your full name"
              className="w-full px-4 py-2.5 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800/60 text-slate-900 dark:text-white placeholder-slate-400 text-sm focus:outline-none focus:border-blue-500 focus:ring-4 focus:ring-blue-100 dark:focus:ring-blue-900/30 transition-all"
            />
          </div>

          {/* Email Address Field */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="text-sm font-semibold text-slate-800 dark:text-slate-200">
                Email Address
              </label>
              <span className="text-xs text-slate-400">Required</span>
            </div>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="e.g. abc@gmail.com"
              className="w-full px-4 py-2.5 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800/60 text-slate-900 dark:text-white placeholder-slate-400 text-sm focus:outline-none focus:border-blue-500 focus:ring-4 focus:ring-blue-100 dark:focus:ring-blue-900/30 transition-all"
            />
          </div>

          {/* Blue Sign In & Proceed Action Button */}
          <button
            type="submit"
            disabled={loading}
            className="w-full py-3.5 px-4 rounded-xl bg-[#4F6BF5] hover:bg-[#3D5AF0] active:scale-[0.99] text-white font-medium text-sm flex items-center justify-center gap-2 shadow-sm transition-all disabled:opacity-60 cursor-pointer mt-2"
          >
            {loading ? (
              <span className="flex items-center gap-2">
                <span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                Signing In...
              </span>
            ) : (
              <span>Sign In &amp; Proceed &rarr;</span>
            )}
          </button>
        </form>

      </div>
    </div>
  );
}
