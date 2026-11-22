import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          950: "#050811",
          900: "#0b1222",
          850: "#10192e",
          800: "#16223d",
          700: "#1e2f52",
          border: "#1f2e4d",
          cyan: "#00f0ff",
          blue: "#0284c7",
          safe: "#10b981",
          caution: "#f59e0b",
          suspicious: "#f97316",
          danger: "#ef4444",
        },
      },
      animation: {
        "radar": "radar 4s linear infinite",
        "scan-beam": "scanBeam 3s ease-in-out infinite",
        "shimmer": "shimmer 2.5s linear infinite",
        "pulse-glow": "pulseGlow 2s ease-in-out infinite",
      },
      keyframes: {
        radar: {
          "0%": { transform: "rotate(0deg)" },
          "100%": { transform: "rotate(360deg)" },
        },
        scanBeam: {
          "0%, 100%": { transform: "translateY(0%)", opacity: "0.2" },
          "50%": { transform: "translateY(100%)", opacity: "0.9" },
        },
        shimmer: {
          "0%": { backgroundPosition: "-200% 0" },
          "100%": { backgroundPosition: "200% 0" },
        },
        pulseGlow: {
          "0%, 100%": { opacity: "0.4", transform: "scale(1)" },
          "50%": { opacity: "0.9", transform: "scale(1.03)" },
        },
      },
    },
  },
  plugins: [],
};

export default config;
