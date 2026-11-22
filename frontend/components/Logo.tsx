"use client";

import React from "react";

interface LogoProps {
  className?: string;
  size?: number;
  showText?: boolean;
}

export default function Logo({ className = "", size = 36, showText = false }: LogoProps) {
  return (
    <div className={`inline-flex items-center gap-2.5 select-none ${className}`}>
      {/* Precision Dual-Blade Cyber Shield */}
      <svg
        width={size}
        height={size}
        viewBox="0 0 64 64"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="flex-shrink-0 drop-shadow-[0_4px_12px_rgba(0,242,254,0.35)]"
      >
        <defs>
          <linearGradient id="compBladeLeft" x1="12" y1="8" x2="32" y2="56" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#00F2FE" />
            <stop offset="100%" stopColor="#0066FF" />
          </linearGradient>
          <linearGradient id="compBladeRight" x1="52" y1="8" x2="32" y2="56" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#38BDF8" />
            <stop offset="100%" stopColor="#1E40AF" />
          </linearGradient>
          <filter id="coreGlowComp" x="-30%" y="-30%" width="160%" height="160%">
            <feGaussianBlur stdDeviation="1.6" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
        </defs>

        <path
          d="M30.5 8 L12 17 V33.5 C12 45.8 20.5 53.2 30.5 56.8 V35.5 L21.5 28.5 L30.5 22 V8 Z"
          fill="url(#compBladeLeft)"
        />

        <path
          d="M33.5 8 L52 17 V33.5 C52 45.8 43.5 53.2 33.5 56.8 V35.5 L42.5 28.5 L33.5 22 V8 Z"
          fill="url(#compBladeRight)"
        />

        <polygon
          points="32,22.5 37.5,28.5 32,34.5 26.5,28.5"
          fill="#00F2FE"
          filter="url(#coreGlowComp)"
        />
        <polygon points="32,41.5 35.5,45.5 32,49.5 28.5,45.5" fill="#38BDF8" />
      </svg>

      {showText && (
        <div className="flex items-center gap-1.5">
          <span className="font-extrabold text-lg tracking-tight text-slate-900 dark:text-white">
            ScamShield
          </span>
          <span className="text-cyan-400 font-mono text-[11px] font-bold uppercase px-1.5 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/30">
            AI
          </span>
        </div>
      )}
    </div>
  );
}
