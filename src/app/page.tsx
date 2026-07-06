import Link from "next/link";

export default function LandingPage() {
  return (
    <div className="flex min-h-screen flex-col bg-slate-950 text-slate-100 font-sans selection:bg-accent selection:text-slate-950 relative">

      <header className="sticky top-0 z-50 border-b border-white/8 bg-slate-950/92 backdrop-blur">
        <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-5">
          <Link href="/" className="flex items-center space-x-3 cursor-pointer group">
            <div className="p-1.5 bg-accent/12 border border-accent/25 rounded-md group-hover:border-accent/50 transition-colors duration-200">
              <svg className="w-5 h-5 text-accent" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5">
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <span className="font-mono text-base font-bold tracking-tight text-white">
              Patch<span className="text-accent">Pilot</span>
            </span>
          </Link>
          <div className="flex items-center space-x-6">
            <Link 
              href="/scanner" 
              className="text-xs font-mono tracking-wider uppercase text-slate-400 hover:text-white transition-colors cursor-pointer"
            >
              Scanner
            </Link>
            <Link
              href="/scanner?case=sql-injection"
              className="group inline-flex items-center justify-center rounded-md bg-accent px-4 py-2 text-[11px] font-bold uppercase tracking-wider text-slate-950 transition-colors duration-200 hover:bg-accent-hover cursor-pointer active:translate-y-px"
            >
              Demo scan
            </Link>
          </div>
        </div>
      </header>

      {/* Hero Section - Product Pitch and Primary CTAs */}
      <main className="flex-grow">
        <section className="relative overflow-hidden border-b border-white/8 py-20 md:py-28">
          <div className="mx-auto grid max-w-6xl items-center gap-14 px-5 lg:grid-cols-12">
            
            {/* Left Content Column */}
            <div className="lg:col-span-7 space-y-8 text-left">
              <div className="inline-flex items-center gap-2 border-l-2 border-accent pl-3">
                <span className="text-[10px] font-mono uppercase tracking-[0.18em] font-medium text-slate-400">Local scanner / patch drafts</span>
              </div>
              
              <h1 className="text-4xl md:text-6xl font-display font-extrabold tracking-tighter text-white leading-[1.05] text-balance">
                Find risky code paths before review turns slow.
              </h1>
              
              <p className="text-base md:text-lg text-slate-400 leading-relaxed max-w-xl">
                PatchPilot checks pasted code and public GitHub files for common security mistakes, then returns concrete remediation notes and diff-ready patch suggestions.
              </p>
              
              <div className="flex flex-wrap items-center gap-3">
                <Link
                  href="/scanner?case=sql-injection"
                  className="inline-flex items-center justify-center rounded-md bg-accent px-5 py-3 text-xs font-bold uppercase tracking-wider text-slate-950 transition-colors duration-200 hover:bg-accent-hover cursor-pointer active:translate-y-px"
                >
                  Run demo scan
                </Link>
                <Link
                  href="/scanner"
                  className="inline-flex items-center justify-center rounded-md border border-white/10 bg-slate-900/60 px-5 py-3 text-xs font-semibold uppercase tracking-wider text-white transition-colors duration-200 hover:bg-slate-800/70 cursor-pointer active:translate-y-px"
                >
                  Open scanner
                </Link>
              </div>
            </div>

            {/* Right Visual Column (Double-Bezel Code Diff Mockup) */}
            <div className="lg:col-span-5 relative">
              <div className="border border-white/10 bg-slate-900/55 shadow-2xl shadow-black/50">
                <div className="bg-slate-950 border border-white/5 overflow-hidden">
                  <div className="bg-slate-900/70 px-5 py-3.5 border-b border-white/8 flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <div className="w-2.5 h-2.5 rounded-sm bg-red-500/70" />
                      <div className="w-2.5 h-2.5 rounded-sm bg-yellow-500/70" />
                      <div className="w-2.5 h-2.5 rounded-sm bg-accent/70" />
                    </div>
                    <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest">query-safety.diff</span>
                  </div>
                  <div className="p-6 font-mono text-[11px] overflow-x-auto leading-relaxed text-left">
                    <div className="text-slate-600 mb-2 font-bold select-none">@@ -1,3 +1,3 @@</div>
                    <div className="text-slate-400 mb-1 select-none">  // Unsafe query string build</div>
                    <div className="bg-red-500/10 text-red-400 px-3.5 py-2.5 border-l-2 border-red-500 my-2 flex items-start">
                      <span className="mr-3 font-bold select-none text-red-500/50">-</span>
                      <span className="break-all">const sql = &#96;SELECT * FROM accounts WHERE id = &#36;&#123;id&#125;&#96;;</span>
                    </div>
                    <div className="bg-emerald-500/10 text-emerald-400 px-3.5 py-2.5 border-l-2 border-accent my-2 flex items-start">
                      <span className="mr-3 font-bold select-none text-emerald-500/50">+</span>
                      <span className="break-all">const sql = &apos;SELECT * FROM accounts WHERE id = ?&apos;;</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>

          </div>
        </section>

        {/* Step-by-Step Flow Section */}
        <section className="py-20 bg-slate-900/20 relative overflow-hidden">
          <div className="max-w-6xl mx-auto px-5">
            <div className="text-left max-w-2xl mb-20 space-y-4">
              <span className="text-[10px] font-mono uppercase tracking-[0.2em] text-accent font-bold">Workflow</span>
              <h2 className="text-3xl md:text-5xl font-display font-extrabold text-white tracking-tight leading-none">
                From snippet to review note.
              </h2>
            </div>
            
            <div className="grid md:grid-cols-3 gap-8">
              {[
                {
                  step: "01",
                  title: "Load code",
                  desc: "Paste a snippet or pull a public GitHub file into the scanner workspace."
                },
                {
                  step: "02",
                  title: "Run rules",
                  desc: "Deterministic checks flag common injection, secret, CORS, path, and logging risks."
                },
                {
                  step: "03",
                  title: "Review patch",
                  desc: "Read the finding, inspect evidence, and copy the safer replacement or report."
                }
              ].map((item, idx) => (
                <div key={idx} className="relative group">
                  <div className="border border-white/8 bg-slate-950 p-6 transition-colors duration-200 group-hover:border-accent/30">
                    <div className="space-y-4 text-left">
                      <div className="font-mono text-3xl font-black text-accent/25 tracking-tighter">{item.step}</div>
                      <h3 className="text-base font-bold text-white tracking-tight">{item.title}</h3>
                      <p className="text-xs text-slate-400 leading-relaxed">{item.desc}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Feature system */}
        <section className="border-t border-white/8 py-20">
          <div className="max-w-6xl mx-auto px-5">
            <div className="text-left max-w-2xl mb-20 space-y-4">
              <span className="text-[10px] font-mono uppercase tracking-[0.2em] text-accent font-bold">Capabilities</span>
              <h2 className="text-3xl md:text-5xl font-display font-extrabold text-white tracking-tight leading-none">
                What the scanner returns.
              </h2>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              
              {/* Box 1 (Span 2) */}
              <div className="md:col-span-2 border border-white/8 bg-slate-950 p-8 h-full flex flex-col justify-between text-left space-y-8">
                  <div className="space-y-3">
                    <span className="text-[9px] font-mono uppercase tracking-wider text-accent">Confidentiality</span>
                    <h3 className="text-xl font-bold text-white tracking-tight">Client-side checks</h3>
                    <p className="text-xs text-slate-400 leading-relaxed max-w-md">
                      Pasted code is evaluated against deterministic rules in the browser workflow instead of being sent to a model endpoint.
                    </p>
                  </div>
                  <div className="flex space-x-2 pt-4 border-t border-white/5 font-mono text-[10px] text-slate-500">
                    <span>Local scan</span>
                    <span>&bull;</span>
                    <span>No AI upload required</span>
                  </div>
              </div>

              <div className="border border-white/8 bg-slate-950 p-8 h-full flex flex-col justify-between text-left space-y-6">
                  <div className="space-y-3">
                    <span className="text-[9px] font-mono uppercase tracking-wider text-red-400">Security</span>
                    <h3 className="text-xl font-bold text-white tracking-tight">Secret redaction</h3>
                    <p className="text-xs text-slate-400 leading-relaxed">
                      API tokens and credentials (like `sk-...`) are automatically masked inside reports, logs, and outputs.
                    </p>
                  </div>
                  <div className="font-mono text-[9px] bg-slate-900 px-3 py-1.5 rounded-lg text-slate-500 select-none truncate">
                    sk-proj-aB1c...REDACTED...s8T9u
                  </div>
              </div>

              <div className="border border-white/8 bg-slate-950 p-8 h-full flex flex-col justify-between text-left space-y-6">
                  <div className="space-y-3">
                    <span className="text-[9px] font-mono uppercase tracking-wider text-blue-400">Integrations</span>
                    <h3 className="text-xl font-bold text-white tracking-tight">Repository scans</h3>
                    <p className="text-xs text-slate-400 leading-relaxed">
                      Pull whole public repositories dynamically. Scans compatible codebase files recursively.
                    </p>
                  </div>
                  <div className="font-mono text-[10px] text-slate-500">
                    Recursive &bull; Max 25 Files
                  </div>
              </div>

              <div className="md:col-span-2 border border-white/8 bg-slate-950 p-8 h-full flex flex-col justify-between text-left space-y-8">
                  <div className="space-y-3">
                    <span className="text-[9px] font-mono uppercase tracking-wider text-emerald-400">Compliance</span>
                    <h3 className="text-xl font-bold text-white tracking-tight">CWE and OWASP mapping</h3>
                    <p className="text-xs text-slate-400 leading-relaxed max-w-md">
                      Every finding maps directly to recognized standards (e.g., CWE-89 for SQL Injection, CWE-798 for Secrets) and OWASP Top 10 categories, supporting audit readiness.
                    </p>
                  </div>
                  <div className="flex space-x-2 pt-4 border-t border-white/5 font-mono text-[10px] text-slate-500">
                    <span>Audit ready</span>
                    <span>&bull;</span>
                    <span>Standard references</span>
                  </div>
              </div>

            </div>
          </div>
        </section>

        {/* Vulnerability coverage */}
        <section className="border-t border-white/8 py-20 bg-slate-900/20">
          <div className="max-w-6xl mx-auto px-5">
            <div className="text-left max-w-2xl mb-20 space-y-4">
              <span className="text-[10px] font-mono uppercase tracking-[0.2em] text-accent font-bold">Coverage</span>
              <h2 className="text-3xl md:text-5xl font-display font-extrabold text-white tracking-tight leading-none">
                Detection coverage.
              </h2>
            </div>

            <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
              {[
                { title: "Hardcoded secrets", severity: "Critical", desc: "API keys, secret tokens, private credentials, and AWS access IDs embedded in scripts." },
                { title: "SQL injection", severity: "Critical", desc: "Queries that combine user input through template strings or concatenation." },
                { title: "Command injection", severity: "Critical", desc: "Shell commands that pass raw input into host runtime calls." },
                { title: "Unsafe eval", severity: "High", desc: "Dynamic JavaScript or Python execution through eval-style APIs." },
                { title: "Insecure CORS", severity: "High", desc: "Wildcard origin settings combined with credential access." },
                { title: "Path traversal", severity: "High", desc: "File access that accepts user-controlled directory navigation." },
                { title: "Weak token generation", severity: "Medium", desc: "Predictable random values used near auth token or reset flows." },
                { title: "Sensitive logging", severity: "Medium", desc: "Log output that includes passwords, keys, tokens, or private payloads." }
              ].map((vuln, idx) => (
                <div key={idx} className="p-6 border border-white/8 bg-slate-950 hover:border-accent/25 transition-colors duration-200 text-left flex flex-col justify-between min-h-[180px]">
                  <div className="flex items-center justify-between mb-4">
                    <span className={`px-2 py-0.5 rounded text-[9px] font-mono font-bold uppercase ${
                      vuln.severity === "Critical" ? "bg-red-500/10 text-red-400 border border-red-500/20" :
                      vuln.severity === "High" ? "bg-orange-500/10 text-orange-400 border border-orange-500/20" :
                      "bg-yellow-500/10 text-yellow-400 border border-yellow-500/20"
                    }`}>
                      {vuln.severity}
                    </span>
                  </div>
                  <div className="space-y-2">
                    <h3 className="text-sm font-bold text-white tracking-tight">{vuln.title}</h3>
                    <p className="text-xs text-slate-400 leading-relaxed">{vuln.desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-white/8 bg-slate-950 py-14 relative z-10">
        <div className="max-w-6xl mx-auto px-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-8">
          <div className="text-left space-y-2">
            <div className="font-mono text-base font-bold text-white">PatchPilot</div>
            <p className="text-xs text-slate-500 max-w-sm leading-relaxed">
              Deterministic static analysis for common code review risks. Review every patch suggestion before production use.
            </p>
          </div>
          <div className="flex flex-col sm:items-end space-y-2 text-xs text-slate-500">
            <div className="flex flex-wrap gap-x-4 gap-y-2">
              <Link href="/scanner" className="hover:text-slate-300">Scanner Workspace</Link>
              <span className="text-slate-700" aria-disabled="true">Privacy</span>
              <span className="text-slate-700" aria-disabled="true">Terms</span>
            </div>
            <span>&copy; {new Date().getFullYear()} PatchPilot. All rights reserved.</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
