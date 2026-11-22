"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { 
  ShieldCheck, 
  LayoutDashboard, 
  Globe, 
  MessageSquareWarning, 
  Briefcase, 
  History, 
  Sun, 
  Moon, 
  LogIn, 
  LogOut, 
  User, 
  Menu,
  X,
  Home
} from "lucide-react";
import Logo from "@/components/Logo";

export default function Navbar() {
  const pathname = usePathname();
  const [isDark, setIsDark] = useState(true);
  const [user, setUser] = useState<{ name: string; email: string; picture?: string } | null>(null);
  const [sideDrawerOpen, setSideDrawerOpen] = useState(false);

  useEffect(() => {
    const savedTheme = localStorage.getItem("scamshield_theme");
    const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    const shouldBeDark = savedTheme ? savedTheme === "dark" : prefersDark;
    
    setIsDark(shouldBeDark);
    if (shouldBeDark) {
      document.documentElement.classList.add("dark");
    } else {
      document.documentElement.classList.remove("dark");
    }

    const syncUser = () => {
      const savedUser = localStorage.getItem("scamshield_user");
      if (savedUser) {
        try {
          setUser(JSON.parse(savedUser));
        } catch {
          setUser(null);
        }
      } else {
        setUser(null);
      }
    };

    syncUser();
    window.addEventListener("auth_change", syncUser);
    window.addEventListener("storage", syncUser);

    return () => {
      window.removeEventListener("auth_change", syncUser);
      window.removeEventListener("storage", syncUser);
    };
  }, []);

  const toggleTheme = () => {
    const nextTheme = !isDark;
    setIsDark(nextTheme);
    if (nextTheme) {
      document.documentElement.classList.add("dark");
      localStorage.setItem("scamshield_theme", "dark");
    } else {
      document.documentElement.classList.remove("dark");
      localStorage.setItem("scamshield_theme", "light");
    }
  };

  const handleLogout = () => {
    localStorage.removeItem("scamshield_token");
    localStorage.removeItem("scamshield_user");
    setUser(null);
    window.dispatchEvent(new Event("auth_change"));
    window.location.href = "/dashboard";
  };

  const drawerLinks = [
    { name: "Home", href: "/", icon: Home },
    { name: "Dashboard", href: "/dashboard", icon: LayoutDashboard },
    { name: "URL Scanner", href: "/scan/url", icon: Globe },
    { name: "Message Scanner", href: "/scan/message", icon: MessageSquareWarning },
    { name: "Job Verifier", href: "/scan/job", icon: Briefcase },
  ];

  return (
    <>
      <nav className="sticky top-0 z-50 backdrop-blur-md bg-white/90 dark:bg-cyber-950/90 border-b border-slate-200 dark:border-slate-800 transition-colors">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            
            {/* Left: Three Lines Hamburger Menu + Logo and Name */}
            <div className="flex items-center gap-3">
              {/* Three Lines Menu Icon */}
              <button
                onClick={() => setSideDrawerOpen(true)}
                aria-label="Open Navigation Drawer"
                className="p-2 rounded-lg border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-200 hover:text-cyan-500 hover:border-cyan-500 transition-all flex items-center justify-center cursor-pointer"
              >
                <Menu className="w-5 h-5" />
              </button>

              {/* Logo and Name */}
              <Link href="/" prefetch={true} className="flex items-center gap-2 group">
                <Logo size={34} showText={true} />
              </Link>
            </div>

            {/* Right: History, Light/Dark Mode, Sign In */}
            <div className="flex items-center gap-3">
              
              {/* History Button */}
              <Link
                href="/history"
                prefetch={true}
                className={`flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold transition-all ${
                  pathname === "/history"
                    ? "bg-cyan-500/15 text-cyan-600 dark:text-cyan-400 border border-cyan-500/30"
                    : "text-slate-600 dark:text-slate-300 hover:text-cyan-500 hover:bg-slate-100 dark:hover:bg-slate-800/60"
                }`}
              >
                <History className="w-4 h-4" />
                <span>History</span>
              </Link>

              {/* Theme Toggle Button */}
              <button
                onClick={toggleTheme}
                aria-label="Toggle Theme"
                className="p-2 rounded-lg border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-300 hover:text-cyan-500 hover:bg-slate-100 dark:hover:bg-slate-800/80 transition-colors cursor-pointer"
              >
                {isDark ? (
                  <Sun className="w-4 h-4 text-amber-400" />
                ) : (
                  <Moon className="w-4 h-4 text-slate-700" />
                )}
              </button>

              {/* User Profile or Sign In */}
              {user ? (
                <div className="flex items-center gap-2 pl-2 border-l border-slate-200 dark:border-slate-800">
                  {user.picture ? (
                    <img
                      src={user.picture}
                      alt={user.name}
                      className="w-8 h-8 rounded-full border border-cyan-500/50"
                    />
                  ) : (
                    <div className="w-8 h-8 rounded-full bg-cyan-600/20 text-cyan-400 flex items-center justify-center border border-cyan-500/30">
                      <User className="w-4 h-4" />
                    </div>
                  )}
                  <span className="text-xs font-semibold text-slate-800 dark:text-slate-200 hidden sm:inline-block truncate max-w-[100px]">
                    {user.name}
                  </span>
                  <button
                    onClick={handleLogout}
                    title="Sign Out"
                    className="p-1.5 text-slate-400 hover:text-rose-500 transition-colors cursor-pointer"
                  >
                    <LogOut className="w-4 h-4" />
                  </button>
                </div>
              ) : (
                <Link
                  href="/login"
                  prefetch={true}
                  className="cyber-btn flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-bold bg-gradient-to-r from-cyan-500 to-blue-600 text-white shadow-md shadow-cyan-500/25 hover:brightness-110 active:scale-95 transition-all"
                >
                  <LogIn className="w-3.5 h-3.5" />
                  <span>Sign In</span>
                </Link>
              )}

            </div>

          </div>
        </div>
      </nav>

      {/* Slide-over Drawer for the Three Lines Menu */}
      {sideDrawerOpen && (
        <div className="fixed inset-0 z-50 flex">
          {/* Backdrop */}
          <div
            className="fixed inset-0 bg-slate-950/60 backdrop-blur-sm transition-opacity"
            onClick={() => setSideDrawerOpen(false)}
          />

          {/* Drawer content */}
          <div className="relative w-72 max-w-[80vw] bg-white dark:bg-cyber-950 border-r border-slate-200 dark:border-slate-800 p-6 flex flex-col justify-between shadow-2xl z-10 transition-transform">
            
            <div className="space-y-6">
              {/* Drawer Header */}
              <div className="flex items-center justify-between pb-4 border-b border-slate-200 dark:border-slate-800">
                <div className="flex items-center gap-2">
                  <Logo size={24} />
                  <span className="font-bold text-sm text-slate-900 dark:text-white font-mono">
                    ScamShield AI
                  </span>
                </div>
                <button
                  onClick={() => setSideDrawerOpen(false)}
                  className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* Drawer Navigation Links */}
              <div className="space-y-1">
                {drawerLinks.map((item) => {
                  const Icon = item.icon;
                  const isActive = pathname === item.href;
                  return (
                    <Link
                      key={item.name}
                      href={item.href}
                      prefetch={true}
                      onClick={() => setSideDrawerOpen(false)}
                      className={`flex items-center gap-3 px-3.5 py-3 rounded-xl text-xs font-semibold transition-all ${
                        isActive
                          ? "bg-cyan-500/15 text-cyan-500 border border-cyan-500/30"
                          : "text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800/80 hover:text-cyan-400"
                      }`}
                    >
                      <Icon className="w-4 h-4 text-cyan-500" />
                      <span>{item.name}</span>
                    </Link>
                  );
                })}
              </div>
            </div>

            {/* Drawer Bottom Info */}
            <div className="pt-4 border-t border-slate-200 dark:border-slate-800 text-[11px] font-mono text-slate-500">
              <span>ScamShield AI Platform v1.0.0</span>
            </div>

          </div>
        </div>
      )}
    </>
  );
}
