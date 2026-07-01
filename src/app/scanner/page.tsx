"use client";

import React, { useState, useEffect, Suspense } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import Link from "next/link";
import { demoCases } from "../../../lib/scanner/demoCases";
import { Finding, ScanResult } from "../../../lib/scanner/scan";

function ScannerClient() {
  const searchParams = useSearchParams();
  const router = useRouter();

  // Languages supported
  const languages = [
    { value: "javascript", label: "JavaScript" },
    { value: "typescript", label: "TypeScript" },
    { value: "python", label: "Python" }
  ];

  // The currently selected programming language for the scan
  const [language, setLanguage] = useState<string>("javascript");
  // The current code text content inside the editor textarea
  const [code, setCode] = useState<string>("");
  // The ID of the currently loaded demo case, if any
  const [selectedCaseId, setSelectedCaseId] = useState<string>("");
  
  // The aggregated scan output result containing findings and score
  const [result, setResult] = useState<ScanResult | null>(null);
  // Loader state while contacting the API scan endpoint
  const [isScanning, setIsScanning] = useState<boolean>(false);
  // The ID of the currently selected vulnerability finding card
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  // Success notification text banner message
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Hydrates the workspace state from URL query parameters (e.g. ?case=sql-injection&lang=python) on mount.
  // This allows the landing page CTAs to route directly into a pre-configured demo case.
  useEffect(() => {
    const caseParam = searchParams.get("case");
    const langParam = searchParams.get("lang");

    let initialLang = "javascript";
    if (langParam && ["javascript", "typescript", "python"].includes(langParam.toLowerCase())) {
      initialLang = langParam.toLowerCase();
    }
    setLanguage(initialLang);

    if (caseParam) {
      const matchedCase = demoCases.find(c => c.id === caseParam);
      if (matchedCase) {
        setSelectedCaseId(matchedCase.id);
        const demoCode = matchedCase.languages[initialLang as "javascript" | "typescript" | "python"];
        setCode(demoCode || "");
      }
    }
  }, [searchParams]);

  // Handle language change
  const handleLanguageChange = (newLang: string) => {
    setLanguage(newLang);
    // If a demo case is currently loaded, reload that case's code in the new language
    if (selectedCaseId) {
      const matchedCase = demoCases.find(c => c.id === selectedCaseId);
      if (matchedCase) {
        setCode(matchedCase.languages[newLang as "javascript" | "typescript" | "python"] || "");
      }
    }
  };

  // Handle demo case selection
  const handleCaseChange = (caseId: string) => {
    setSelectedCaseId(caseId);
    if (caseId) {
      const matchedCase = demoCases.find(c => c.id === caseId);
      if (matchedCase) {
        setCode(matchedCase.languages[language as "javascript" | "typescript" | "python"] || "");
      }
    } else {
      setCode("");
    }
  };

  // Perform API-based code scan
  const runScan = async () => {
    setIsScanning(true);
    setResult(null);
    setSelectedFindingId(null);
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ language, code })
      });

      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.error || "Failed to scan code.");
      }

      const data: ScanResult = await res.json();
      setResult(data);
      if (data.findings && data.findings.length > 0) {
        setSelectedFindingId(data.findings[0].id);
      }
    } catch (err: any) {
      alert(err.message || "An error occurred.");
    } finally {
      setIsScanning(false);
    }
  };

  // Replace vulnerable lines with safer patch suggestion
  const applyFix = (finding: Finding) => {
    // Split the current editor code into individual lines
    const lines = code.split("\n");
    // Extract the unchanged lines preceding the vulnerability
    const beforeLines = lines.slice(0, finding.lineStart - 1);
    // Extract the unchanged lines following the vulnerability
    const afterLines = lines.slice(finding.lineEnd);
    
    // Splice in the recommended patch replacement and join back with newlines
    const newCode = [...beforeLines, finding.patch.after, ...afterLines].join("\n");
    setCode(newCode);

    // Trigger an automatic background re-audit on the updated code
    setIsScanning(true);
    fetch("/api/scan", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ language, code: newCode })
    })
      .then(res => res.json())
      .then((data: ScanResult) => {
        setResult(data);
        setSelectedFindingId(null);
        // Display a success banner notifying the user that the code was patched
        setSuccessMessage("Safer patch successfully applied to editor!");
        setTimeout(() => setSuccessMessage(null), 4000);
      })
      .catch(() => {
        alert("Applied fix, but failed to re-scan automatically.");
      })
      .finally(() => {
        setIsScanning(false);
      });
  };

  // Copy safe snippet to clipboard
  const copySnippet = (text: string) => {
    navigator.clipboard.writeText(text);
    alert("Safer replacement code copied to clipboard!");
  };

  // Get active selected finding
  const selectedFinding = result?.findings.find(f => f.id === selectedFindingId);

  // Stats helpers
  const getSeverityCount = (sev: string) => {
    return result?.findings.filter(f => f.severity === sev).length || 0;
  };

  // Custom Git-style unified diff renderer.
  // Parses patch diff text and highlights removed lines in red and added lines in green.
  const renderDiff = (diff: string) => {
    const lines = diff.split("\n");
    return (
      <pre className="font-mono text-xs overflow-x-auto p-4 rounded-lg bg-slate-950 border border-slate-900 leading-relaxed max-w-full">
        {lines.map((line, i) => {
          let className = "text-slate-400";
          if (line.startsWith("-")) {
            className = "bg-red-500/10 text-red-400 px-2 py-0.5 border-l-2 border-red-500 block my-0.5";
          } else if (line.startsWith("+")) {
            className = "bg-green-500/10 text-green-400 px-2 py-0.5 border-l-2 border-accent block my-0.5";
          } else if (line.startsWith("@@")) {
            className = "text-slate-600 block py-0.5";
          }
          return (
            <code key={i} className={className}>
              {line}
              {"\n"}
            </code>
          );
        })}
      </pre>
    );
  };

  return (
    <div className="flex flex-col min-h-screen bg-slate-950 text-slate-100 font-sans selection:bg-accent selection:text-slate-950">
      {/* Header */}
      <header className="border-b border-slate-900 bg-slate-950">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <Link href="/" className="flex items-center space-x-3 cursor-pointer">
            <div className="p-2 bg-accent/10 border border-accent/25 rounded-lg">
              <svg className="w-5 h-5 text-accent" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <span className="font-mono text-lg font-bold tracking-tight text-white">
              Patch<span className="text-accent">Pilot</span>
            </span>
          </Link>
          <div className="flex items-center space-x-2 text-xs font-mono bg-slate-900 border border-slate-800/80 px-3 py-1 rounded-full text-slate-400">
            <span className="w-1.5 h-1.5 rounded-full bg-accent animate-pulse" />
            <span>Local Engine Mode</span>
          </div>
        </div>
      </header>

      {/* Main Grid */}
      <main className="flex-grow max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid lg:grid-cols-5 gap-8 items-start">
          
          {/* Left Panel: Code Input (Takes 3 cols on lg screens) */}
          <div className="lg:col-span-3 space-y-4">
            <div className="bg-slate-900/40 border border-slate-900 rounded-2xl p-4 backdrop-blur-sm">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-4">
                {/* Selectors */}
                <div className="flex flex-wrap items-center gap-3">
                  {/* Language Selector */}
                  <div className="flex flex-col">
                    <label className="text-[10px] font-mono text-slate-500 uppercase tracking-wide mb-1">Language</label>
                    <select
                      value={language}
                      onChange={(e) => handleLanguageChange(e.target.value)}
                      className="bg-slate-900 border border-slate-800 text-xs text-slate-200 rounded-lg px-3 py-1.5 outline-none focus:border-accent cursor-pointer"
                    >
                      {languages.map((l) => (
                        <option key={l.value} value={l.value}>{l.label}</option>
                      ))}
                    </select>
                  </div>

                  {/* Case Selector */}
                  <div className="flex flex-col">
                    <label className="text-[10px] font-mono text-slate-500 uppercase tracking-wide mb-1">Load Demo case</label>
                    <select
                      value={selectedCaseId}
                      onChange={(e) => handleCaseChange(e.target.value)}
                      className="bg-slate-900 border border-slate-800 text-xs text-slate-200 rounded-lg px-3 py-1.5 outline-none focus:border-accent cursor-pointer"
                    >
                      <option value="">-- Choose Vulnerability --</option>
                      {demoCases.map((c) => (
                        <option key={c.id} value={c.id}>{c.name}</option>
                      ))}
                    </select>
                  </div>
                </div>

                {/* Reset button */}
                <button
                  onClick={() => { setCode(""); setSelectedCaseId(""); setResult(null); setSelectedFindingId(null); }}
                  className="sm:self-end text-xs text-slate-500 hover:text-slate-300 font-mono transition-colors cursor-pointer py-1"
                >
                  Clear Code
                </button>
              </div>

              {/* Editor TextArea */}
              <div className="relative">
                <textarea
                  value={code}
                  onChange={(e) => { setCode(e.target.value); setSelectedCaseId(""); }}
                  placeholder="// Paste your JavaScript, TypeScript, or Python code here..."
                  className="font-mono text-xs text-slate-100 bg-slate-950 border border-slate-900 rounded-xl p-4 w-full h-[500px] resize-none outline-none focus:border-accent/40 focus:ring-1 focus:ring-accent/20 transition-all leading-relaxed"
                  spellCheck="false"
                />
              </div>

              {/* Action Trigger */}
              <div className="flex items-center justify-between mt-4">
                <span className="text-[11px] text-slate-500 font-mono">
                  Deterministic static analysis scans code client-side.
                </span>
                <button
                  onClick={runScan}
                  disabled={isScanning || !code.trim()}
                  className="inline-flex items-center justify-center px-5 py-2.5 text-xs font-semibold text-slate-950 bg-accent hover:bg-accent-hover disabled:bg-slate-800 disabled:text-slate-500 rounded-xl shadow-lg hover:shadow-accent/15 transition-all cursor-pointer disabled:cursor-not-allowed"
                >
                  {isScanning ? (
                    <>
                      <svg className="animate-spin -ml-1 mr-2 h-4.5 w-4.5 text-slate-950" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                      </svg>
                      Analyzing...
                    </>
                  ) : (
                    <>
                      Run Scan
                      <svg className="w-4 h-4 ml-1.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M14 5l7 7m0 0l-7 7m7-7H3" />
                      </svg>
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* In-app notification */}
            {successMessage && (
              <div className="p-3 bg-accent/10 border border-accent/20 rounded-xl text-accent text-xs font-mono flex items-center space-x-2">
                <svg className="w-4.5 h-4.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <span>{successMessage}</span>
              </div>
            )}
          </div>

          {/* Right Panel: Findings Details (Takes 2 cols on lg screens) */}
          <div className="lg:col-span-2 space-y-4">
            
            {/* Empty State */}
            {!result && !isScanning && (
              <div className="border border-slate-900 rounded-2xl p-8 bg-slate-900/10 text-center flex flex-col items-center justify-center min-h-[450px]">
                <div className="p-4 bg-slate-900 rounded-full border border-slate-800 text-slate-500 mb-4">
                  <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.5">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                </div>
                <h3 className="text-sm font-bold text-white mb-2">Audit Ready</h3>
                <p className="text-xs text-slate-500 max-w-xs leading-relaxed">
                  Select a vulnerability case from the dropdown or paste your own script, then trigger <span className="font-mono text-slate-400">Run Scan</span> to inspect static patterns.
                </p>
              </div>
            )}

            {/* Scan Loader Mock */}
            {isScanning && !result && (
              <div className="border border-slate-900 rounded-2xl p-8 bg-slate-900/10 text-center flex flex-col items-center justify-center min-h-[450px]">
                <div className="w-10 h-10 border-2 border-slate-800 border-t-accent rounded-full animate-spin mb-4" />
                <h3 className="text-sm font-bold text-white mb-2">Analyzing Patterns...</h3>
                <p className="text-xs text-slate-500">Executing rules line-by-line in sandboxed workspace.</p>
              </div>
            )}

            {/* Scan Results Panel */}
            {result && (
              <div className="space-y-4">
                
                {/* Score & Severity stats */}
                <div className="grid grid-cols-2 gap-4">
                  
                  {/* Security Score gauge block */}
                  <div className="border border-slate-900 rounded-2xl p-4 bg-slate-900/20 flex flex-col justify-between">
                    <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wide">Security Score</span>
                    <div className="my-3 flex items-baseline">
                      <span className={`text-4xl font-extrabold font-mono ${
                        result.score >= 90 ? "text-green-400" :
                        result.score >= 70 ? "text-yellow-400" :
                        result.score >= 50 ? "text-orange-400" :
                        "text-red-500"
                      }`}>
                        {result.score}
                      </span>
                      <span className="text-slate-500 text-xs font-mono ml-1">/100</span>
                    </div>
                    <span className={`text-[10px] font-semibold tracking-wider uppercase inline-flex items-center`}>
                      <span className={`w-1.5 h-1.5 rounded-full mr-1.5 ${
                        result.score >= 90 ? "bg-green-400" :
                        result.score >= 70 ? "bg-yellow-400" :
                        result.score >= 50 ? "bg-orange-400" :
                        "bg-red-500"
                      }`} />
                      {result.score >= 90 ? "Secure" :
                       result.score >= 70 ? "Warning" :
                       result.score >= 50 ? "Vulnerable" :
                       "High Risk"}
                    </span>
                  </div>

                  {/* Severity Counters Grid */}
                  <div className="border border-slate-900 rounded-2xl p-4 bg-slate-900/20 grid grid-cols-2 gap-2 text-center">
                    <div className="p-1.5 border border-slate-950 bg-slate-950/40 rounded-lg">
                      <div className="text-red-500 font-mono font-bold text-sm">{getSeverityCount("critical")}</div>
                      <div className="text-[9px] text-slate-500 uppercase tracking-wide">Critical</div>
                    </div>
                    <div className="p-1.5 border border-slate-950 bg-slate-950/40 rounded-lg">
                      <div className="text-orange-400 font-mono font-bold text-sm">{getSeverityCount("high")}</div>
                      <div className="text-[9px] text-slate-500 uppercase tracking-wide">High</div>
                    </div>
                    <div className="p-1.5 border border-slate-950 bg-slate-950/40 rounded-lg">
                      <div className="text-yellow-400 font-mono font-bold text-sm">{getSeverityCount("medium")}</div>
                      <div className="text-[9px] text-slate-500 uppercase tracking-wide">Medium</div>
                    </div>
                    <div className="p-1.5 border border-slate-950 bg-slate-950/40 rounded-lg">
                      <div className="text-blue-400 font-mono font-bold text-sm">{getSeverityCount("low")}</div>
                      <div className="text-[9px] text-slate-500 uppercase tracking-wide">Low</div>
                    </div>
                  </div>
                </div>

                {/* Summary Text */}
                <div className="p-3 border border-slate-900 rounded-xl bg-slate-900/10 text-xs text-slate-400 font-mono leading-relaxed">
                  {result.summary}
                </div>

                {/* Findings Deck List */}
                {result.findings.length > 0 ? (
                  <div className="space-y-2">
                    <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wide">Findings Detected ({result.findings.length})</div>
                    <div className="max-h-[300px] overflow-y-auto space-y-2 pr-1">
                      {result.findings.map((finding) => (
                        <div
                          key={finding.id}
                          onClick={() => setSelectedFindingId(finding.id)}
                          className={`p-3.5 border rounded-xl cursor-pointer transition-all flex items-start justify-between ${
                            selectedFindingId === finding.id
                              ? "bg-slate-900/60 border-slate-700/80 shadow-md"
                              : "bg-slate-900/20 border-slate-900 hover:border-slate-800"
                          }`}
                        >
                          <div className="space-y-1">
                            <h4 className="text-xs font-bold text-white leading-snug">{finding.title}</h4>
                            <div className="flex items-center space-x-2 text-[10px] font-mono text-slate-500">
                              <span>Lines {finding.lineStart}-{finding.lineEnd}</span>
                              <span>&bull;</span>
                              <span>{finding.category}</span>
                            </div>
                          </div>

                          <span className={`px-2 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider ${
                            finding.severity === "critical" ? "bg-red-500/10 text-red-400 border border-red-500/20" :
                            finding.severity === "high" ? "bg-orange-500/10 text-orange-400 border border-orange-500/20" :
                            finding.severity === "medium" ? "bg-yellow-500/10 text-yellow-400 border border-yellow-500/20" :
                            "bg-blue-500/10 text-blue-400 border border-blue-500/20"
                          }`}>
                            {finding.severity}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <div className="border border-slate-900 rounded-2xl p-6 bg-slate-900/10 text-center">
                    <svg className="w-6 h-6 text-accent mx-auto mb-2" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <span className="text-xs text-slate-400">All checks passed. No vulns found!</span>
                  </div>
                )}

                {/* Selected Finding Details */}
                {selectedFinding && (
                  <div className="border border-slate-900 rounded-2xl p-5 bg-slate-900/40 space-y-4 backdrop-blur-sm animate-fadeIn">
                    
                    {/* Header Info */}
                    <div className="flex items-center justify-between pb-3 border-b border-slate-900">
                      <div>
                        <h3 className="text-sm font-bold text-white">{selectedFinding.title}</h3>
                        <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wide">{selectedFinding.category}</span>
                      </div>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                        selectedFinding.severity === "critical" ? "bg-red-500/10 text-red-400 border border-red-500/20" :
                        selectedFinding.severity === "high" ? "bg-orange-500/10 text-orange-400 border border-orange-500/20" :
                        selectedFinding.severity === "medium" ? "bg-yellow-500/10 text-yellow-400 border border-yellow-500/20" :
                        "bg-blue-500/10 text-blue-400 border border-blue-500/20"
                      }`}>
                        {selectedFinding.severity}
                      </span>
                    </div>

                    {/* Explanation */}
                    <div className="space-y-1">
                      <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wide block">Risk Explanation</span>
                      <p className="text-xs text-slate-300 leading-relaxed">{selectedFinding.explanation}</p>
                    </div>

                    {/* Recommendation */}
                    <div className="space-y-1">
                      <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wide block">Remediation Suggestion</span>
                      <p className="text-xs text-slate-300 leading-relaxed">{selectedFinding.recommendation}</p>
                    </div>

                    {/* Evidence Snippet */}
                    <div className="space-y-1">
                      <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wide block">Evidence</span>
                      <pre className="font-mono text-xs text-red-300/80 bg-red-950/20 border border-red-900/35 rounded-lg p-3 overflow-x-auto leading-relaxed max-w-full">
                        <code>{selectedFinding.evidence}</code>
                      </pre>
                    </div>

                    {/* Patch Suggestion Diff */}
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wide block">Safer Patch Diff</span>
                        <span className="text-[10px] font-mono text-slate-500">Lines {selectedFinding.lineStart}-{selectedFinding.lineEnd}</span>
                      </div>
                      
                      {renderDiff(selectedFinding.patch.diff)}

                      {/* Actions */}
                      <div className="flex items-center gap-2 pt-2">
                        <button
                          onClick={() => applyFix(selectedFinding)}
                          className="flex-1 inline-flex items-center justify-center px-4 py-2.5 text-xs font-semibold text-slate-950 bg-accent hover:bg-accent-hover rounded-lg transition-colors cursor-pointer"
                        >
                          <svg className="w-4 h-4 mr-1.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                            <path strokeLinecap="round" strokeLinejoin="round" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
                          </svg>
                          Apply Fix to Editor
                        </button>
                        <button
                          onClick={() => copySnippet(selectedFinding.patch.after)}
                          className="px-4 py-2.5 text-xs font-semibold text-slate-200 bg-slate-900 border border-slate-800 hover:bg-slate-800 rounded-lg transition-colors cursor-pointer"
                          title="Copy Replacement Code"
                        >
                          Copy Safe Code
                        </button>
                      </div>
                    </div>

                  </div>
                )}

              </div>
            )}

          </div>

        </div>
      </main>
    </div>
  );
}

export default function ScannerPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center text-slate-400 font-mono space-y-4">
        <div className="w-8 h-8 border-2 border-slate-800 border-t-accent rounded-full animate-spin" />
        <span>Loading PatchPilot Workspace...</span>
      </div>
    }>
      <ScannerClient />
    </Suspense>
  );
}
