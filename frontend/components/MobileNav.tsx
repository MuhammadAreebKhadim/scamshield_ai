"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { 
  Home, 
  LayoutDashboard, 
  Globe, 
  MessageSquareWarning, 
  Briefcase 
} from "lucide-react";

export default function MobileNav() {
  const pathname = usePathname();

  const navItems = [
    { name: "Home", href: "/", icon: Home },
    { name: "Dashboard", href: "/dashboard", icon: LayoutDashboard },
    { name: "URL Scan", href: "/scan/url", icon: Globe },
    { name: "Messages", href: "/scan/message", icon: MessageSquareWarning },
    { name: "Jobs", href: "/scan/job", icon: Briefcase },
  ];

  return (
    <nav 
      aria-label="Mobile Navigation"
      className="fixed bottom-0 left-0 right-0 z-40 md:hidden bg-white/95 dark:bg-cyber-950/95 backdrop-blur-xl border-t border-slate-200 dark:border-slate-800 shadow-[0_-4px_20px_rgba(0,0,0,0.1)] transition-colors"
      style={{ paddingBottom: "max(env(safe-area-inset-bottom, 0px), 6px)" }}
    >
      <div className="grid grid-cols-5 h-14 max-w-md mx-auto items-center px-1">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = pathname === item.href || (item.href !== "/" && pathname.startsWith(item.href));

          return (
            <Link
              key={item.name}
              href={item.href}
              prefetch={true}
              className={`flex flex-col items-center justify-center py-1 transition-all active:scale-90 ${
                isActive
                  ? "text-cyan-500 font-bold"
                  : "text-slate-500 dark:text-slate-400 hover:text-cyan-500"
              }`}
            >
              <div className={`p-1 rounded-lg transition-colors ${isActive ? "bg-cyan-500/15" : ""}`}>
                <Icon className={`w-4 h-4 ${isActive ? "stroke-[2.5]" : "stroke-2"}`} />
              </div>
              <span className={`text-[10px] tracking-tight leading-tight mt-0.5 ${isActive ? "font-bold text-cyan-500" : "font-medium"}`}>
                {item.name}
              </span>
            </Link>
          );
        })}
      </div>
    </nav>
  );
}
