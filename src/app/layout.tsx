import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "PatchPilot - Deterministic Code Security Scanner & Patches",
  description: "Identify common security vulnerabilities in JavaScript, TypeScript, and Python code. Get detailed explanations and download git-style patch remediation suggestions.",
  keywords: ["security scanner", "static code analysis", "security patches", "code audit", "vulnerability remediation", "javascript security", "python security"],
  authors: [{ name: "PatchPilot Team" }]
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="h-full antialiased dark">
      <body className="min-h-full flex flex-col bg-slate-950 text-slate-100 font-sans relative overflow-x-hidden">
        <div className="noise-overlay" aria-hidden="true" />
        {children}
      </body>
    </html>
  );
}
