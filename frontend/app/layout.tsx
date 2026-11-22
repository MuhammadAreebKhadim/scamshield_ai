import type { Metadata } from "next";
import "./globals.css";
import Navbar from "@/components/Navbar";
import Footer from "@/components/Footer";

export const metadata: Metadata = {
  title: "ScamShield AI",
  description: "Unified threat detection and fraud verification intelligence platform.",
  icons: {
    icon: "/favicon.svg",
    shortcut: "/favicon.svg",
    apple: "/favicon.svg",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <head>
        <script src="https://accounts.google.com/gsi/client" async defer></script>
      </head>
      <body className="min-h-screen flex flex-col bg-slate-50 dark:bg-cyber-950 text-slate-900 dark:text-slate-100 selection:bg-cyan-500 selection:text-white">
        <Navbar />
        <main className="flex-1 cyber-grid">
          {children}
        </main>
        <Footer />
      </body>
    </html>
  );
}
