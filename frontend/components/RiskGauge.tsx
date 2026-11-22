import React from "react";
import { ShieldCheck, ShieldAlert, AlertTriangle, ShieldX } from "lucide-react";

interface RiskGaugeProps {
  score: number;
  level: "LOW" | "CAUTION" | "SUSPICIOUS" | "HIGH";
  isThreatConfirmed?: boolean;
  size?: "sm" | "md" | "lg";
}

export default function RiskGauge({ score, level, isThreatConfirmed, size = "md" }: RiskGaugeProps) {
  // Clamp score
  const safeScore = Math.min(Math.max(score, 0), 100);

  // SVG dimensions
  const dimensions = size === "lg" ? 200 : size === "sm" ? 120 : 160;
  const strokeWidth = size === "lg" ? 14 : size === "sm" ? 8 : 12;
  const radius = (dimensions - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (safeScore / 100) * circumference;

  let colorClasses = {
    stroke: "#10b981", // emerald
    bgBadge: "bg-emerald-500/15 border-emerald-500/30 text-emerald-500",
    textClass: "text-emerald-500",
    label: "Low Risk",
    Icon: ShieldCheck,
  };

  if (level === "HIGH" || safeScore >= 70) {
    colorClasses = {
      stroke: "#ef4444", // rose
      bgBadge: "bg-rose-500/15 border-rose-500/30 text-rose-500",
      textClass: "text-rose-500",
      label: "High Risk",
      Icon: ShieldX,
    };
  } else if (level === "SUSPICIOUS" || safeScore >= 40) {
    colorClasses = {
      stroke: "#f97316", // orange
      bgBadge: "bg-orange-500/15 border-orange-500/30 text-orange-500",
      textClass: "text-orange-500",
      label: "Suspicious",
      Icon: ShieldAlert,
    };
  } else if (level === "CAUTION" || safeScore >= 20) {
    colorClasses = {
      stroke: "#f59e0b", // amber
      bgBadge: "bg-amber-500/15 border-amber-500/30 text-amber-500",
      textClass: "text-amber-500",
      label: "Caution",
      Icon: AlertTriangle,
    };
  }

  const { Icon } = colorClasses;

  return (
    <div className="flex flex-col items-center justify-center text-center p-4">
      <div className="relative" style={{ width: dimensions, height: dimensions }}>
        <svg
          className="transform -rotate-90"
          width={dimensions}
          height={dimensions}
        >
          {/* Background circle track */}
          <circle
            cx={dimensions / 2}
            cy={dimensions / 2}
            r={radius}
            stroke="currentColor"
            strokeWidth={strokeWidth}
            className="text-slate-200 dark:text-slate-800"
            fill="transparent"
          />
          {/* Progress circle */}
          <circle
            cx={dimensions / 2}
            cy={dimensions / 2}
            r={radius}
            stroke={colorClasses.stroke}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            className="transition-all duration-1000 ease-out"
            fill="transparent"
          />
        </svg>

        {/* Center content */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <Icon className={`w-6 h-6 ${colorClasses.textClass} mb-1`} />
          <span className={`font-mono font-extrabold ${size === 'lg' ? 'text-4xl' : 'text-3xl'} ${colorClasses.textClass}`}>
            {safeScore}
          </span>
          <span className="text-[11px] font-mono text-slate-500 uppercase tracking-widest">
            / 100
          </span>
        </div>
      </div>

      {/* Level classification badge */}
      <div className="mt-3 flex flex-col items-center gap-1.5">
        <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold uppercase tracking-wider border ${colorClasses.bgBadge}`}>
          <span className="w-1.5 h-1.5 rounded-full bg-current"></span>
          {colorClasses.label}
        </span>

        {isThreatConfirmed && (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-rose-600 text-white font-bold tracking-wider">
            Threat Confirmed
          </span>
        )}
      </div>
    </div>
  );
}
