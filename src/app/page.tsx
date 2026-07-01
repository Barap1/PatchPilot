import Link from "next/link";

export default function LandingPage() {
  return (
    <div className="flex flex-col min-h-screen bg-slate-950 text-slate-100 font-sans selection:bg-accent selection:text-slate-950">
      {/* Header */}
      <header className="sticky top-0 z-50 border-b border-slate-900 bg-slate-950/80 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-accent/10 border border-accent/25 rounded-lg">
              <svg className="w-6 h-6 text-accent" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <span className="font-mono text-xl font-bold tracking-tight text-white">
              Patch<span className="text-accent">Pilot</span>
            </span>
          </div>
          <div className="flex items-center space-x-4">
            <Link 
              href="/scanner" 
              className="text-sm font-medium text-slate-400 hover:text-white transition-colors cursor-pointer"
            >
              Scanner
            </Link>
            <Link
              href="/scanner?case=sql-injection"
              className="inline-flex items-center justify-center px-4 py-2 text-xs font-semibold tracking-wide text-slate-950 bg-accent hover:bg-accent-hover rounded-lg shadow-lg hover:shadow-accent/20 transition-all cursor-pointer"
            >
              Try Demo Scan
            </Link>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <main className="flex-grow">
        <section className="relative overflow-hidden py-24 md:py-32">
          {/* Decorative glow */}
          <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full max-w-7xl h-96 bg-radial from-accent/5 to-transparent blur-3xl pointer-events-none" />
          
          <div className="max-w-4xl mx-auto text-center px-4 relative z-10">
            <div className="inline-flex items-center space-x-2 px-3 py-1.5 rounded-full border border-slate-800 bg-slate-900/60 mb-6 backdrop-blur">
              <span className="flex h-2 w-2 relative">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-accent opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-accent"></span>
              </span>
              <span className="text-xs font-medium text-slate-400">100% Deterministic Rule Engine</span>
            </div>
            
            <h1 className="text-4xl md:text-6xl font-mono font-bold tracking-tight text-white mb-6 leading-tight">
              Find risky code patterns and generate <span className="text-accent underline decoration-accent/30 decoration-wavy">safer patches</span>.
            </h1>
            
            <p className="text-lg md:text-xl text-slate-400 mb-10 leading-relaxed max-w-2xl mx-auto">
              PatchPilot scans code for common security mistakes, explains the risk, and creates patch-style remediation suggestions instantly.
            </p>
            
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <Link
                href="/scanner?case=sql-injection"
                className="w-full sm:w-auto inline-flex items-center justify-center px-6 py-3.5 text-sm font-semibold text-slate-950 bg-accent hover:bg-accent-hover rounded-xl shadow-xl hover:shadow-accent/15 transition-all cursor-pointer"
              >
                Try Demo Scan
                <svg className="w-4 h-4 ml-2" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
              </Link>
              <Link
                href="/scanner"
                className="w-full sm:w-auto inline-flex items-center justify-center px-6 py-3.5 text-sm font-semibold text-white bg-slate-900 border border-slate-800 hover:bg-slate-800 rounded-xl transition-all cursor-pointer"
              >
                Paste Code
              </Link>
            </div>
          </div>
        </section>

        {/* How It Works Section */}
        <section className="border-t border-slate-900 py-20 bg-slate-900/10">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="text-center max-w-2xl mx-auto mb-16">
              <h2 className="text-3xl font-mono font-bold text-white mb-4">How it works</h2>
              <p className="text-slate-400">Scan, audit, and patch vulnerabilities in three simple steps.</p>
            </div>
            
            <div className="grid md:grid-cols-3 gap-8">
              {[
                {
                  step: "01",
                  title: "Input Code",
                  desc: "Paste your JavaScript, TypeScript, or Python code directly into the editor, or choose one of our built-in vulnerable test cases."
                },
                {
                  step: "02",
                  title: "Run Scan",
                  desc: "PatchPilot runs code through a suite of deterministic static analysis rules, checking for patterns that commonly host critical security risks."
                },
                {
                  step: "03",
                  title: "Apply Patch",
                  desc: "Review inline findings, examine the danger breakdown, and view clean, side-by-side git patch diffs to safely secure your code."
                }
              ].map((item, idx) => (
                <div key={idx} className="relative p-6 border border-slate-900 rounded-2xl bg-slate-900/30">
                  <div className="font-mono text-4xl font-extrabold text-accent/25 mb-4">{item.step}</div>
                  <h3 className="text-lg font-bold text-white mb-2">{item.title}</h3>
                  <p className="text-sm text-slate-400 leading-relaxed">{item.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Vulnerabilities Detected Section */}
        <section className="border-t border-slate-900 py-20">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="text-center max-w-2xl mx-auto mb-16">
              <h2 className="text-3xl font-mono font-bold text-white mb-4">Vulnerabilities Detected</h2>
              <p className="text-slate-400">We inspect codebases for these critical and high-priority pattern families.</p>
            </div>

            <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
              {[
                { title: "Hardcoded Secrets", severity: "Critical", desc: "API keys, secret tokens, private credentials, and AWS access IDs embedded directly in scripts." },
                { title: "SQL Injection", severity: "Critical", desc: "Unsanitized queries combining user input using string template literals or concatenations." },
                { title: "Command Injection", severity: "Critical", desc: "Sys shell executions passing raw inputs directly to operational host runtimes." },
                { title: "Unsafe Eval", severity: "High", desc: "Usage of eval() or dynamic Function constructors allowing arbitrary input execution." },
                { title: "Insecure CORS", severity: "High", desc: "Origin configurations matching wildcards (*) mixed with credential access flags." },
                { title: "Path Traversal", severity: "High", desc: "File access queries incorporating user-controlled directory navigation keys." },
                { title: "Weak Token Gen", severity: "Medium", desc: "Predictable pseudo-random generators utilized in authentication token routines." },
                { title: "Sensitive Logging", severity: "Medium", desc: "Terminal debugging lines logging raw passwords, auth keys, or private payload logs." }
              ].map((vuln, idx) => (
                <div key={idx} className="p-5 border border-slate-900 rounded-xl bg-slate-900/20 hover:border-slate-800 transition-colors">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-sm font-bold text-white font-mono">{vuln.title}</h3>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-semibold tracking-wider uppercase ${
                      vuln.severity === "Critical" ? "bg-red-500/10 text-red-400 border border-red-500/20" :
                      vuln.severity === "High" ? "bg-orange-500/10 text-orange-400 border border-orange-500/20" :
                      "bg-yellow-500/10 text-yellow-400 border border-yellow-500/20"
                    }`}>
                      {vuln.severity}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">{vuln.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Example Patch Preview Section */}
        <section className="border-t border-slate-900 py-20 bg-slate-900/10">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="grid lg:grid-cols-2 gap-12 items-center">
              <div>
                <span className="text-xs font-bold uppercase tracking-wider text-accent font-mono">Remediation Mock</span>
                <h2 className="text-3xl font-mono font-bold text-white mt-2 mb-6">Real patch suggestions</h2>
                <p className="text-slate-400 mb-6 leading-relaxed">
                  PatchPilot doesn't just call out bugs. For every detected issue, it generates a git-style patch suggestion that provides a safe replacement.
                </p>
                <div className="space-y-4">
                  {[
                    "Saves developer time on secure rewrites",
                    "Teaches secure coding practices inline",
                    "Provides exact line placements for target modifications"
                  ].map((bullet, idx) => (
                    <div key={idx} className="flex items-center space-x-3">
                      <svg className="w-5 h-5 text-accent flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                      </svg>
                      <span className="text-sm text-slate-300">{bullet}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Diff Code Card */}
              <div className="border border-slate-900 rounded-2xl bg-slate-950 overflow-hidden shadow-2xl">
                <div className="bg-slate-900/50 px-4 py-3 border-b border-slate-900 flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <div className="w-3.5 h-3.5 rounded-full bg-red-500/70" />
                    <div className="w-3.5 h-3.5 rounded-full bg-yellow-500/70" />
                    <div className="w-3.5 h-3.5 rounded-full bg-green-500/70" />
                  </div>
                  <span className="text-xs font-mono text-slate-500">sql-injection.patch</span>
                </div>
                <div className="p-5 font-mono text-xs overflow-x-auto leading-relaxed">
                  <div className="text-slate-500 mb-2">@@ -5,2 +5,2 @@</div>
                  <div className="bg-red-500/10 text-red-400 px-3 py-1.5 rounded border-l-2 border-red-500 my-1 flex items-start">
                    <span className="mr-2 select-none">-</span>
                    <span>const query = `SELECT * FROM users WHERE id = ${userId}`;</span>
                  </div>
                  <div className="bg-green-500/10 text-green-400 px-3 py-1.5 rounded border-l-2 border-accent my-1 flex items-start">
                    <span className="mr-2 select-none">+</span>
                    <span>const query = &apos;SELECT * FROM users WHERE id = ?&apos;; // Use parameterized values</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Why Deterministic Scanning Matters Section */}
        <section className="border-t border-slate-900 py-20">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="text-center max-w-2xl mx-auto mb-16">
              <h2 className="text-3xl font-mono font-bold text-white mb-4">Why Deterministic Scanning Matters</h2>
              <p className="text-slate-400">Secure code scanning should be immediate, secure, and run locally.</p>
            </div>

            <div className="grid md:grid-cols-3 gap-8">
              {[
                {
                  title: "Zero Data Leakage",
                  desc: "We perform all scans locally inside the browser memory. Your proprietary source code never travels to a server or external LLM API."
                },
                {
                  title: "100% Deterministic",
                  desc: "Static rules produce predictable, repeatable scan outcomes. No hallucinatory or erratic security findings."
                },
                {
                  title: "No Latency, No Cost",
                  desc: "Immediate results. Free from network latency or LLM API usage bills, making it easy to run scans repeatedly on every keypress."
                }
              ].map((item, idx) => (
                <div key={idx} className="p-6 border border-slate-900 rounded-2xl bg-slate-900/10">
                  <h3 className="text-lg font-bold text-white mb-3">{item.title}</h3>
                  <p className="text-sm text-slate-400 leading-relaxed">{item.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center sm:text-left flex flex-col sm:flex-row items-center justify-between gap-6">
          <div>
            <div className="font-mono text-md font-bold text-white mb-2">PatchPilot</div>
            <p className="text-xs text-slate-500 max-w-md">
              Disclaimer: PatchPilot is a focused static pattern analyzer designed for specific risky code blocks. It does not replace comprehensive audits or catch all edge cases.
            </p>
          </div>
          <div className="text-xs text-slate-500">
            &copy; {new Date().getFullYear()} PatchPilot. All rights reserved.
          </div>
        </div>
      </footer>
    </div>
  );
}
