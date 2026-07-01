"use client";

import React, { useState, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { demoCases } from "../../../lib/scanner/demoCases";
import { Finding, ScanResult } from "../../../lib/scanner/scan";
import { ruleDocs } from "../../../lib/scanner/ruleDocs";
import { rules } from "../../../lib/scanner/rules";

// Helper to extract rule ID from finding ID
function getRuleId(findingId: string): string {
  const cleanId = findingId.includes(":") ? findingId.split(":")[0] : findingId;
  const lastHyphen = cleanId.lastIndexOf("-");
  return lastHyphen !== -1 ? cleanId.substring(0, lastHyphen) : cleanId;
}

// --- Report Export Helpers ---

const generateMarkdownReport = (result: ScanResult, repoName?: string, branchName?: string) => {
  const isRepo = !!repoName;
  let md = `# PatchPilot Security Scan Report\n\n`;
  md += `- **Scan Timestamp:** ${new Date().toLocaleString()}\n`;
  if (isRepo) {
    md += `- **GitHub Repository:** ${repoName}\n`;
    md += `- **Branch:** ${branchName}\n`;
    md += `- **Files Scanned:** ${result.findings.length ? new Set(result.findings.map(f => f.id.split(":")[1] || "editor")).size : 1}\n`;
  } else {
    md += `- **Target Language:** ${result.language}\n`;
  }
  md += `- **Security Score:** ${result.score}/100\n`;
  md += `- **Total Findings:** ${result.findings.length}\n\n`;
  
  const critical = result.findings.filter(f => f.severity === "critical").length;
  const high = result.findings.filter(f => f.severity === "high").length;
  const medium = result.findings.filter(f => f.severity === "medium").length;
  const low = result.findings.filter(f => f.severity === "low").length;
  
  md += `## Severity Summary\n`;
  md += `- **Critical:** ${critical}\n`;
  md += `- **High:** ${high}\n`;
  md += `- **Medium:** ${medium}\n`;
  md += `- **Low:** ${low}\n\n`;
  
  md += `## Vulnerability Findings\n\n`;
  if (result.findings.length === 0) {
    md += `No security vulnerabilities detected. Code appears clean under deterministic scanning rules.\n`;
  } else {
    result.findings.forEach((finding, idx) => {
      const fileContext = isRepo ? ` (${finding.id.split(":")[1] || "unknown file"})` : "";
      md += `### ${idx + 1}. ${finding.title}${fileContext}\n`;
      md += `- **Rule ID:** \`${getRuleId(finding.id)}\`\n`;
      md += `- **Severity:** \`${finding.severity.toUpperCase()}\`\n`;
      md += `- **Confidence:** \`${finding.confidence.toUpperCase()}\`\n`;
      md += `- **CWE:** [${finding.cwe}](https://cwe.mitre.org/data/definitions/${finding.cwe.split("-")[1]}.html)\n`;
      md += `- **OWASP:** \`${finding.owasp}\`\n`;
      md += `- **Line Range:** Lines ${finding.lineStart} - ${finding.lineEnd}\n`;
      md += `- **Matched Because:** *${finding.matchedBecause}*\n\n`;
      
      md += `#### Risk Explanation\n${finding.explanation}\n\n`;
      md += `#### Remediation Suggestion\n${finding.recommendation}\n\n`;
      
      md += `#### Evidence Snippet\n\`\`\`\n${finding.evidence}\n\`\`\`\n\n`;
      md += `#### Safer Patch Suggestion\n\`\`\`diff\n${finding.patch.diff}\n\`\`\`\n\n`;
      md += `---\n\n`;
    });
  }
  
  md += `## Report Limitations Disclaimer\n`;
  md += `PatchPilot is a focused static-pattern security scanner, not a full compiler/AST SAST engine. Findings are deterministic and reproducible. All suggested patch suggestions should be reviewed and verified before production use. Secrets are fully redacted in all report outputs.\n`;
  
  return md;
};

const generateSarifReport = (result: ScanResult) => {
  const sarif = {
    $schema: "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "PatchPilot",
            version: "1.0.0",
            rules: rules.map(rule => ({
              id: rule.id,
              name: rule.title,
              shortDescription: { text: rule.title },
              fullDescription: { text: rule.explanation },
              help: { text: rule.recommendation },
              properties: {
                cwe: rule.cwe,
                owasp: rule.owasp,
                severity: rule.severity,
                confidence: rule.confidence
              }
            }))
          }
        },
        results: result.findings.map(finding => {
          // In repo scan, the file path is stored in the finding ID or location metadata
          const filePath = finding.id.includes(":") ? finding.id.split(":")[1] : "pasted-code-editor";
          return {
            ruleId: getRuleId(finding.id),
            message: { text: `${finding.matchedBecause}\n\nRecommendation: ${finding.recommendation}` },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: {
                    uri: filePath
                  },
                  region: {
                    startLine: finding.lineStart,
                    endLine: finding.lineEnd
                  }
                }
              }
            ],
            properties: {
              severity: finding.severity,
              confidence: finding.confidence
            }
          };
        })
      }
    ]
  };
  return JSON.stringify(sarif, null, 2);
};

export interface RepoScanFileResult {
  path: string;
  language: string;
  score: number;
  findings: Finding[];
}

export interface RepoScanSkippedFile {
  path: string;
  reason: string;
}

export interface RepoScanResult {
  repo: string;
  branch: string;
  filesScanned: number;
  filesSkipped: number;
  score: number;
  summary: string;
  results: RepoScanFileResult[];
  skipped: RepoScanSkippedFile[];
}

// --- Main component ---

function ScannerClient() {
  const searchParams = useSearchParams();

  // Hydrate states from searchParams directly on initialization
  const caseParam = searchParams.get("case");
  const langParam = searchParams.get("lang");
  
  let initialLang = "javascript";
  if (langParam && ["javascript", "typescript", "python"].includes(langParam.toLowerCase())) {
    initialLang = langParam.toLowerCase();
  }

  const initialCase = caseParam || "";
  const matchedCase = demoCases.find(c => c.id === initialCase);
  const initialCode = matchedCase ? (matchedCase.languages[initialLang as "javascript" | "typescript" | "python"] || "") : "";

  // Languages supported
  const languages = [
    { value: "javascript", label: "JavaScript" },
    { value: "typescript", label: "TypeScript" },
    { value: "python", label: "Python" }
  ];

  // Active Workspace Mode Tab: "editor" | "github-file" | "github-repo"
  const [activeTab, setActiveTab] = useState<"editor" | "github-file" | "github-repo">(caseParam ? "editor" : "editor");

  // Single File Editor Workspace States
  const [language, setLanguage] = useState<string>(initialLang);
  const [code, setCode] = useState<string>(initialCode);
  const [selectedCaseId, setSelectedCaseId] = useState<string>(initialCase);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [sourcePath, setSourcePath] = useState<string | null>(null);

  // GitHub Single File Import States
  const [githubFileUrl, setGithubFileUrl] = useState<string>("");
  const [isFileLoading, setIsFileLoading] = useState<boolean>(false);

  // GitHub Repository Scan States
  const [githubRepoUrl, setGithubRepoUrl] = useState<string>("");
  const [githubBranch, setGithubBranch] = useState<string>("main");
  const [repoResult, setRepoResult] = useState<RepoScanResult | null>(null);
  const [isRepoScanning, setIsRepoScanning] = useState<boolean>(false);
  const [expandedRepoFiles, setExpandedRepoFiles] = useState<Record<string, boolean>>({});

  // Finding Detail Selection States
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [isDocExpanded, setIsDocExpanded] = useState<boolean>(false);

  // AI Explanation States
  const [aiExplanation, setAiExplanation] = useState<{
    beginnerExplanation: string;
    secureFixExplanation: string;
    interviewSummary: string;
    caveats: string;
  } | null>(null);
  const [isAiLoading, setIsAiLoading] = useState<boolean>(false);
  const [aiError, setAiError] = useState<string | null>(null);

  // Handle language change
  const handleLanguageChange = (newLang: string) => {
    setLanguage(newLang);
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

  // Perform Editor Code static analysis
  const runScan = async () => {
    setIsScanning(true);
    setResult(null);
    setSelectedFindingId(null);
    setAiExplanation(null);
    setAiError(null);
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
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
    } catch (err: unknown) {
      alert((err as Error).message || "An error occurred.");
    } finally {
      setIsScanning(false);
    }
  };

  // Fetch file from GitHub URL
  const importGithubFile = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!githubFileUrl.trim()) return;

    setIsFileLoading(true);
    try {
      const res = await fetch("/api/github/file", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: githubFileUrl.trim() })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to load file from GitHub.");
      }

      setCode(data.code);
      setLanguage(data.language);
      setSourcePath(`${data.owner}/${data.repo}/${data.branch}: ${data.path}`);
      setResult(null);
      setSelectedFindingId(null);
      setAiExplanation(null);
      setSuccessMessage(`Successfully imported ${data.path}!`);
      setActiveTab("editor");
      setTimeout(() => setSuccessMessage(null), 4000);
    } catch (err: unknown) {
      alert((err as Error).message || "Failed to import GitHub file.");
    } finally {
      setIsFileLoading(false);
    }
  };

  // Execute Repository Scan
  const runRepositoryScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!githubRepoUrl.trim()) return;

    setIsRepoScanning(true);
    setRepoResult(null);
    setSelectedFindingId(null);
    setAiExplanation(null);
    setAiError(null);
    try {
      const res = await fetch("/api/github/repo-scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          repoUrl: githubRepoUrl.trim(),
          branch: githubBranch.trim()
        })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to scan repository.");
      }

      setRepoResult(data);
      
      // Auto-expand files that have findings
      const expanded: Record<string, boolean> = {};
      data.results.forEach((r: RepoScanFileResult) => {
        if (r.findings && r.findings.length > 0) {
          expanded[r.path] = true;
        }
      });
      setExpandedRepoFiles(expanded);

      // Auto-select first finding if available
      const allFindings = data.results.flatMap((r: RepoScanFileResult) => 
        r.findings.map((f: Finding) => ({ ...f, filePath: r.path }))
      );
      if (allFindings.length > 0) {
        // Tag finding ID with file path to identify it uniquely
        setSelectedFindingId(`${allFindings[0].id}:${allFindings[0].filePath}`);
      }
    } catch (err: unknown) {
      alert((err as Error).message || "Failed to run repository scan.");
    } finally {
      setIsRepoScanning(false);
    }
  };

  // Apply safe patch to code editor
  const applyFix = (finding: Finding) => {
    let newCode = "";
    
    if (finding.patch.replacementMode === "range") {
      // Exact character replacement mapping
      newCode = 
        code.substring(0, finding.patch.replacementStart) + 
        finding.patch.after + 
        code.substring(finding.patch.replacementEnd);
    } else {
      // Full line splicing replacement
      const lines = code.split("\n");
      const beforeLines = lines.slice(0, finding.lineStart - 1);
      const afterLines = lines.slice(finding.lineEnd);
      newCode = [...beforeLines, finding.patch.after, ...afterLines].join("\n");
    }

    setCode(newCode);
    setAiExplanation(null);
    setAiError(null);

    // Auto-rescan after applying fix
    setIsScanning(true);
    fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ language, code: newCode })
    })
      .then(res => {
        if (!res.ok) throw new Error();
        return res.json();
      })
      .then((data: ScanResult) => {
        setResult(data);
        setSelectedFindingId(null);
        setSuccessMessage("Safe patch successfully applied to editor!");
        setTimeout(() => setSuccessMessage(null), 4000);
      })
      .catch(() => {
        alert("Applied fix, but failed to re-scan automatically.");
      })
      .finally(() => {
        setIsScanning(false);
      });
  };

  // Fetch AI-powered explanation
  const fetchAiExplanation = async (finding: Finding) => {
    setIsAiLoading(true);
    setAiExplanation(null);
    setAiError(null);

    // Gather surrounding context (lines -10 to +10 of the finding)
    const lines = code.split("\n");
    const startCtx = Math.max(0, finding.lineStart - 11);
    const endCtx = Math.min(lines.length, finding.lineEnd + 10);
    const codeContext = lines.slice(startCtx, endCtx).join("\n");

    try {
      const res = await fetch("/api/explain-finding", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ finding, codeContext })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to generate AI explanation.");
      }

      setAiExplanation(data);
    } catch (err: unknown) {
      setAiError((err as Error).message || "An error occurred during AI generation.");
    } finally {
      setIsAiLoading(false);
    }
  };

  // Helper to get active selected finding
  const getSelectedFinding = (): Finding | null => {
    if (!selectedFindingId) return null;

    if (activeTab === "github-repo" && repoResult) {
      // Finding ID is formatted as ruleId-idx:filePath
      const [findingId, filePath] = selectedFindingId.split(":");
      const fileRes = repoResult.results.find((r: RepoScanFileResult) => r.path === filePath);
      return fileRes?.findings.find((f: Finding) => f.id === findingId) || null;
    }

    return result?.findings.find(f => f.id === selectedFindingId) || null;
  };

  const selectedFinding = getSelectedFinding();
  const doc = selectedFinding ? ruleDocs[getRuleId(selectedFinding.id)] : null;

  // Stats calculators
  const getSeverityCount = (sev: string) => {
    if (activeTab === "github-repo" && repoResult) {
      return repoResult.results.reduce((acc: number, r: RepoScanFileResult) => 
        acc + r.findings.filter((f: Finding) => f.severity === sev).length
      , 0);
    }
    return result?.findings.filter(f => f.severity === sev).length || 0;
  };

  // File loading helper for repo results
  const loadRepoFileIntoEditor = (path: string, lang: string, fileFindings: Finding[]) => {
    // We can fetch the raw content from GitHub using our API endpoint
    if (!repoResult) return;
    const [owner, repoName] = repoResult.repo.split("/");
    const rawUrl = `https://raw.githubusercontent.com/${owner}/${repoName}/${repoResult.branch}/${path}`;
    
    setIsScanning(true);
    fetch(rawUrl)
      .then(res => {
        if (!res.ok) throw new Error();
        return res.text();
      })
      .then(fileCode => {
        setCode(fileCode);
        setLanguage(lang);
        setSourcePath(`${repoResult.repo}/${repoResult.branch}: ${path}`);
        
        // Re-construct single scan result for editor
        setResult({
          score: 100, // will be re-evaluated
          language: lang,
          summary: `Viewing findings in ${path}`,
          findings: fileFindings
        });
        setActiveTab("editor");
        if (fileFindings.length > 0) {
          setSelectedFindingId(fileFindings[0].id);
        }
      })
      .catch(() => {
        alert("Failed to load file contents from GitHub into editor.");
      })
      .finally(() => {
        setIsScanning(false);
      });
  };

  // Diff download/copy helpers
  const handleCopyText = (text: string, msg: string) => {
    navigator.clipboard.writeText(text);
    alert(msg);
  };

  const handleDownloadFile = (filename: string, content: string) => {
    const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  // Unified diff renderer
  const renderDiff = (diff: string) => {
    const lines = diff.split("\n");
    return (
      <pre className="font-mono text-[11px] overflow-x-auto p-4 rounded-xl bg-slate-950 border border-slate-900 leading-relaxed max-w-full">
        {lines.map((line, i) => {
          let className = "text-slate-400";
          if (line.startsWith("-")) {
            className = "bg-red-500/10 text-red-400 px-2 py-0.5 border-l-2 border-red-500 block my-0.5";
          } else if (line.startsWith("+")) {
            className = "bg-green-500/10 text-green-400 px-2 py-0.5 border-l-2 border-accent block my-0.5";
          } else if (line.startsWith("@@")) {
            className = "text-slate-600 block py-0.5 font-bold";
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

  const getActiveScanResult = (): ScanResult | null => {
    if (activeTab === "github-repo") {
      if (!repoResult) return null;
      return {
        score: repoResult.score,
        language: "multi",
        summary: repoResult.summary,
        findings: repoResult.results.flatMap(r => 
          r.findings.map(f => ({ ...f, id: `${f.id}:${r.path}` }))
        )
      };
    }
    return result;
  };

  const activeScanResult = getActiveScanResult();
  const activeScore = activeScanResult?.score ?? null;

  return (
    <div className="flex flex-col min-h-screen bg-slate-950 text-slate-100 font-sans selection:bg-accent selection:text-slate-950">
      {/* Header */}
      <header className="border-b border-slate-900 bg-slate-950/80 backdrop-blur sticky top-0 z-40">
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
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2 text-xs font-mono bg-slate-900 border border-slate-800/80 px-3 py-1 rounded-full text-slate-400">
              <span className="w-1.5 h-1.5 rounded-full bg-accent animate-pulse" />
              <span>Local Engine Active</span>
            </div>
          </div>
        </div>
      </header>

      {/* Main Grid Workspace */}
      <main className="flex-grow max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid lg:grid-cols-5 gap-8 items-start">
          
          {/* Left Panel: Code Inputs / Import Tabs (3 Columns) */}
          <div className="lg:col-span-3 space-y-4">
            
            {/* Tabs Selector Navigation */}
            <div className="flex border-b border-slate-900">
              <button
                onClick={() => setActiveTab("editor")}
                className={`px-4 py-2.5 font-mono text-xs font-bold transition-all border-b-2 cursor-pointer ${
                  activeTab === "editor"
                    ? "border-accent text-accent bg-accent/5"
                    : "border-transparent text-slate-500 hover:text-slate-300"
                }`}
              >
                Editor Snippet
              </button>
              <button
                onClick={() => setActiveTab("github-file")}
                className={`px-4 py-2.5 font-mono text-xs font-bold transition-all border-b-2 cursor-pointer ${
                  activeTab === "github-file"
                    ? "border-accent text-accent bg-accent/5"
                    : "border-transparent text-slate-500 hover:text-slate-300"
                }`}
              >
                GitHub File Loader
              </button>
              <button
                onClick={() => setActiveTab("github-repo")}
                className={`px-4 py-2.5 font-mono text-xs font-bold transition-all border-b-2 cursor-pointer ${
                  activeTab === "github-repo"
                    ? "border-accent text-accent bg-accent/5"
                    : "border-transparent text-slate-500 hover:text-slate-300"
                }`}
              >
                Repository Scanner
              </button>
            </div>

            {/* TAB CONTENT: Single File Editor Workspace */}
            {activeTab === "editor" && (
              <div className="bg-slate-900/30 border border-slate-900 rounded-2xl p-4 backdrop-blur-sm space-y-4">
                
                {/* Selectors Row */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div className="flex flex-wrap items-center gap-3">
                    {/* Language Selector */}
                    <div className="flex flex-col">
                      <label className="text-[10px] font-mono text-slate-500 uppercase tracking-wide mb-1">Language</label>
                      <select
                        value={language}
                        onChange={(e) => handleLanguageChange(e.target.value)}
                        aria-label="Select programming language"
                        className="bg-slate-950 border border-slate-800 text-xs text-slate-200 rounded-lg px-3 py-1.5 outline-none focus:border-accent cursor-pointer"
                      >
                        {languages.map((l) => (
                          <option key={l.value} value={l.value}>{l.label}</option>
                        ))}
                      </select>
                    </div>

                    {/* Demo Case Selector */}
                    <div className="flex flex-col">
                      <label className="text-[10px] font-mono text-slate-500 uppercase tracking-wide mb-1">Load Demo Case</label>
                      <select
                        value={selectedCaseId}
                        onChange={(e) => handleCaseChange(e.target.value)}
                        aria-label="Select vulnerability demo case"
                        className="bg-slate-950 border border-slate-800 text-xs text-slate-200 rounded-lg px-3 py-1.5 outline-none focus:border-accent cursor-pointer"
                      >
                        <option value="">-- Choose Vulnerability --</option>
                        {demoCases.map((c) => (
                          <option key={c.id} value={c.id}>{c.name}</option>
                        ))}
                      </select>
                    </div>
                  </div>

                  {/* Clear button */}
                  <button
                    onClick={() => { setCode(""); setSelectedCaseId(""); setResult(null); setSelectedFindingId(null); setSourcePath(null); setAiExplanation(null); }}
                    aria-label="Clear code editor content"
                    className="sm:self-end text-xs text-slate-500 hover:text-slate-300 font-mono transition-colors cursor-pointer py-1"
                  >
                    Clear Editor
                  </button>
                </div>

                {/* Editor Textarea */}
                <div className="relative">
                  {sourcePath && (
                    <div className="absolute top-2 left-2 z-10 text-[9px] font-mono text-slate-400 bg-slate-950/80 px-2 py-0.5 rounded border border-slate-800">
                      File: {sourcePath}
                    </div>
                  )}
                  <textarea
                    value={code}
                    onChange={(e) => { setCode(e.target.value); setSelectedCaseId(""); }}
                    placeholder="// Paste your JavaScript, TypeScript, or Python code here..."
                    className="font-mono text-xs text-slate-100 bg-slate-950 border border-slate-900 rounded-xl p-4 pt-8 w-full h-[520px] resize-none outline-none focus:border-accent/40 focus:ring-1 focus:ring-accent/20 transition-all leading-relaxed"
                    spellCheck="false"
                  />
                </div>

                {/* Bottom triggers */}
                <div className="flex items-center justify-between">
                  <span className="text-[10px] text-slate-500 font-mono">
                    Deterministic static scanning runs locally in-memory.
                  </span>
                  <button
                    onClick={runScan}
                    disabled={isScanning || !code.trim()}
                    aria-label="Execute security scan"
                    className="inline-flex items-center justify-center px-5 py-2.5 text-xs font-semibold text-slate-950 bg-accent hover:bg-accent-hover disabled:bg-slate-800 disabled:text-slate-500 rounded-xl shadow-lg hover:shadow-accent/15 transition-all cursor-pointer disabled:cursor-not-allowed"
                  >
                    {isScanning ? (
                      <>
                        <div className="w-3.5 h-3.5 border-2 border-slate-950 border-t-transparent rounded-full animate-spin mr-2" />
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
            )}

            {/* TAB CONTENT: GitHub File Import */}
            {activeTab === "github-file" && (
              <div className="bg-slate-900/30 border border-slate-900 rounded-2xl p-6 backdrop-blur-sm space-y-6">
                <div>
                  <h3 className="text-sm font-bold text-white mb-1">Import from Public GitHub File URL</h3>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Paste a public GitHub blob URL or raw file URL. Only JavaScript (.js, .jsx), TypeScript (.ts, .tsx), and Python (.py) files are supported.
                  </p>
                </div>

                <form onSubmit={importGithubFile} className="space-y-4">
                  <div className="flex flex-col space-y-1">
                    <label className="text-[10px] font-mono text-slate-500 uppercase tracking-wide">GitHub File URL</label>
                    <input
                      type="url"
                      value={githubFileUrl}
                      onChange={(e) => setGithubFileUrl(e.target.value)}
                      placeholder="https://github.com/owner/repo/blob/main/path/to/file.ts"
                      className="bg-slate-950 border border-slate-900 text-xs text-slate-200 rounded-xl px-4 py-3 outline-none focus:border-accent/40 w-full font-mono placeholder:text-slate-700"
                      required
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={isFileLoading || !githubFileUrl.trim()}
                    className="w-full inline-flex items-center justify-center px-4 py-2.5 text-xs font-semibold text-slate-950 bg-accent hover:bg-accent-hover disabled:bg-slate-800 disabled:text-slate-500 rounded-xl transition-all cursor-pointer disabled:cursor-not-allowed"
                  >
                    {isFileLoading ? (
                      <>
                        <div className="w-3.5 h-3.5 border-2 border-slate-950 border-t-transparent rounded-full animate-spin mr-2" />
                        Downloading and Parsing...
                      </>
                    ) : (
                      "Load into Editor"
                    )}
                  </button>
                </form>

                <div className="p-4 rounded-xl border border-slate-900/60 bg-slate-950/20 space-y-2">
                  <h4 className="text-[10px] font-mono text-slate-500 uppercase tracking-wide">Security Safety Labels</h4>
                  <ul className="text-xs text-slate-400 space-y-1 list-disc pl-4 leading-relaxed">
                    <li>Only public GitHub endpoints are contacted; no credentials or OAuth required.</li>
                    <li>Fetches are strictly limited to raw files, timed out at 5s, and capped at 1MB to prevent buffer exhaustion.</li>
                    <li>Downloaded code is loaded statically as text and is never executed inside the browser environment.</li>
                  </ul>
                </div>
              </div>
            )}

            {/* TAB CONTENT: Repository Scanning */}
            {activeTab === "github-repo" && (
              <div className="bg-slate-900/30 border border-slate-900 rounded-2xl p-6 backdrop-blur-sm space-y-6">
                <div>
                  <h3 className="text-sm font-bold text-white mb-1">Public GitHub Codebase Analysis</h3>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Enter the URL of a public repository to scan all contained code scripts. Scans are capped at a maximum of 25 files to preserve API rate limits.
                  </p>
                </div>

                <form onSubmit={runRepositoryScan} className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="md:col-span-2 flex flex-col space-y-1">
                    <label className="text-[10px] font-mono text-slate-500 uppercase tracking-wide">Repository URL</label>
                    <input
                      type="url"
                      value={githubRepoUrl}
                      onChange={(e) => setGithubRepoUrl(e.target.value)}
                      placeholder="https://github.com/owner/repo"
                      className="bg-slate-950 border border-slate-900 text-xs text-slate-200 rounded-xl px-4 py-3 outline-none focus:border-accent/40 w-full font-mono placeholder:text-slate-700"
                      required
                    />
                  </div>
                  <div className="flex flex-col space-y-1">
                    <label className="text-[10px] font-mono text-slate-500 uppercase tracking-wide">Branch</label>
                    <input
                      type="text"
                      value={githubBranch}
                      onChange={(e) => setGithubBranch(e.target.value)}
                      placeholder="main"
                      className="bg-slate-950 border border-slate-900 text-xs text-slate-200 rounded-xl px-4 py-3 outline-none focus:border-accent/40 w-full font-mono placeholder:text-slate-700"
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={isRepoScanning || !githubRepoUrl.trim()}
                    className="md:col-span-3 w-full inline-flex items-center justify-center px-4 py-2.5 text-xs font-semibold text-slate-950 bg-accent hover:bg-accent-hover disabled:bg-slate-800 disabled:text-slate-500 rounded-xl transition-all cursor-pointer disabled:cursor-not-allowed"
                  >
                    {isRepoScanning ? (
                      <>
                        <div className="w-3.5 h-3.5 border-2 border-slate-950 border-t-transparent rounded-full animate-spin mr-2" />
                        Scanning Codebase Files...
                      </>
                    ) : (
                      "Run Repository Scan"
                    )}
                  </button>
                </form>

                {/* Repository Scanning Results */}
                {repoResult && (
                  <div className="space-y-4 border-t border-slate-900 pt-6">
                    <div className="flex items-center justify-between">
                      <h4 className="text-xs font-mono text-slate-500 uppercase tracking-wide">Scanned Files & Findings</h4>
                      <span className="text-[10px] font-mono text-slate-500">Scanned: {repoResult.filesScanned} &bull; Skipped: {repoResult.filesSkipped}</span>
                    </div>

                    <div className="space-y-2 max-h-[300px] overflow-y-auto pr-1">
                      {repoResult.results.length === 0 ? (
                        <div className="text-center text-xs text-slate-500 p-4 border border-slate-900 rounded-xl bg-slate-950/20">
                          No compatible scripting files detected to scan.
                        </div>
                      ) : (
                        repoResult.results.map((fResult: RepoScanFileResult) => (
                          <div key={fResult.path} className="border border-slate-900 rounded-xl bg-slate-950/20 overflow-hidden">
                            <div
                              onClick={() => setExpandedRepoFiles(prev => ({ ...prev, [fResult.path]: !prev[fResult.path] }))}
                              className="px-4 py-3 bg-slate-900/30 flex items-center justify-between cursor-pointer hover:bg-slate-900/50"
                            >
                              <div className="flex items-center space-x-2">
                                <span className="text-xs font-mono font-bold text-slate-200 break-all">{fResult.path}</span>
                                <span className="text-[10px] font-mono text-slate-500 uppercase">({fResult.language})</span>
                              </div>
                              <div className="flex items-center space-x-3">
                                <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                                  fResult.findings.length > 0 ? "bg-red-500/10 text-red-400" : "bg-green-500/10 text-green-400"
                                }`}>
                                  {fResult.findings.length} findings
                                </span>
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    loadRepoFileIntoEditor(fResult.path, fResult.language, fResult.findings);
                                  }}
                                  className="text-[10px] font-mono text-accent hover:underline cursor-pointer"
                                >
                                  Open in Editor
                                </button>
                              </div>
                            </div>

                            {expandedRepoFiles[fResult.path] && fResult.findings.length > 0 && (
                              <div className="border-t border-slate-900 p-2 space-y-1.5 bg-slate-950/40">
                                {fResult.findings.map((f: Finding) => (
                                  <div
                                    key={f.id}
                                    onClick={() => setSelectedFindingId(`${f.id}:${fResult.path}`)}
                                    className={`p-2.5 border rounded-lg cursor-pointer transition-all flex items-center justify-between text-xs ${
                                      selectedFindingId === `${f.id}:${fResult.path}`
                                        ? "bg-slate-900/60 border-slate-700/80"
                                        : "border-transparent bg-transparent hover:border-slate-900 hover:bg-slate-900/20"
                                    }`}
                                  >
                                    <div className="space-y-0.5">
                                      <div className="font-bold text-slate-200">{f.title}</div>
                                      <div className="text-[10px] text-slate-500 font-mono">Lines {f.lineStart}-{f.lineEnd}</div>
                                    </div>
                                    <span className="text-[9px] font-mono font-bold uppercase text-slate-400">{f.severity}</span>
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        ))
                      )}
                    </div>

                    {/* Collapsible Skipped Files list */}
                    {repoResult.skipped && repoResult.skipped.length > 0 && (
                      <details className="group border border-slate-900 rounded-xl bg-slate-950/20">
                        <summary className="px-4 py-2.5 text-xs font-mono font-bold text-slate-500 cursor-pointer hover:text-slate-300 select-none flex items-center justify-between">
                          <span>Skipped/Excluded Files ({repoResult.skipped.length})</span>
                          <span className="transition-transform group-open:rotate-180 font-mono text-[9px]">&darr;</span>
                        </summary>
                        <div className="px-4 pb-3 pt-1 border-t border-slate-900 text-[10px] font-mono text-slate-500 max-h-[150px] overflow-y-auto space-y-1">
                          {repoResult.skipped.map((skip: RepoScanSkippedFile, idx: number) => (
                            <div key={idx} className="flex justify-between py-0.5 border-b border-slate-900/30">
                              <span className="truncate max-w-xs">{skip.path}</span>
                              <span className="text-slate-600">{skip.reason}</span>
                            </div>
                          ))}
                        </div>
                      </details>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* Success Banner */}
            {successMessage && (
              <div className="p-3 bg-accent/10 border border-accent/20 rounded-xl text-accent text-xs font-mono flex items-center space-x-2 animate-fadeIn">
                <svg className="w-4.5 h-4.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <span>{successMessage}</span>
              </div>
            )}
          </div>

          {/* Right Panel: Findings Details (2 Columns) */}
          <div className="lg:col-span-2 space-y-4">
            
            {/* Empty State */}
            {!activeScanResult && !isScanning && !isRepoScanning && (
              <div className="border border-slate-900 rounded-2xl p-8 bg-slate-900/10 text-center flex flex-col items-center justify-center min-h-[450px]">
                <div className="p-4 bg-slate-900 rounded-full border border-slate-800 text-slate-500 mb-4">
                  <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.5">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                </div>
                <h3 className="text-sm font-bold text-white mb-2">Workspace Ready</h3>
                <p className="text-xs text-slate-500 max-w-xs leading-relaxed">
                  Select a vulnerability case from the dropdown or paste your own script, then trigger <span className="font-mono text-slate-400">Run Scan</span> to inspect static patterns.
                </p>
              </div>
            )}

            {/* Loaders */}
            {(isScanning || isRepoScanning) && !activeScanResult && (
              <div className="border border-slate-900 rounded-2xl p-8 bg-slate-900/10 text-center flex flex-col items-center justify-center min-h-[450px]">
                <div className="w-10 h-10 border-2 border-slate-800 border-t-accent rounded-full animate-spin mb-4" />
                <h3 className="text-sm font-bold text-white mb-2">Analyzing Patterns...</h3>
                <p className="text-xs text-slate-500">Executing rules line-by-line in sandboxed workspace.</p>
              </div>
            )}

            {/* Scan Results Deck */}
            {activeScanResult && (
              <div className="space-y-4">
                
                {/* Score & Counters Gauge */}
                <div className="grid grid-cols-2 gap-4">
                  
                  {/* Gauge */}
                  <div className="border border-slate-900 rounded-2xl p-4 bg-slate-900/20 flex flex-col justify-between">
                    <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wide">Security Score</span>
                    <div className="my-3 flex items-baseline">
                      <span className={`text-4xl font-extrabold font-mono ${
                         activeScore! >= 90 ? "text-green-400" :
                         activeScore! >= 70 ? "text-yellow-400" :
                         activeScore! >= 50 ? "text-orange-400" :
                         "text-red-500"
                      }`}>
                        {activeScore}
                      </span>
                      <span className="text-slate-500 text-xs font-mono ml-1">/100</span>
                    </div>
                    <span className={`text-[10px] font-semibold tracking-wider uppercase inline-flex items-center`}>
                      <span className={`w-1.5 h-1.5 rounded-full mr-1.5 ${
                        activeScore! >= 90 ? "bg-green-400" :
                        activeScore! >= 70 ? "bg-yellow-400" :
                        activeScore! >= 50 ? "bg-orange-400" :
                        "bg-red-500"
                      }`} />
                      {activeScore! >= 90 ? "Secure" :
                       activeScore! >= 70 ? "Warning" :
                       activeScore! >= 50 ? "Vulnerable" :
                       "High Risk"}
                    </span>
                  </div>

                  {/* Counters */}
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

                {/* Summary text */}
                <div className="p-3 border border-slate-900 rounded-xl bg-slate-900/10 text-xs text-slate-400 font-mono leading-relaxed">
                  {activeScanResult.summary}
                </div>

                {/* Report Exports Row */}
                <div className="flex flex-wrap items-center gap-2">
                  <button
                    onClick={() => {
                      const md = generateMarkdownReport(activeScanResult, repoResult?.repo, repoResult?.branch);
                      handleCopyText(md, "Markdown report copied to clipboard!");
                    }}
                    className="px-3 py-1.5 border border-slate-800 hover:border-slate-700 bg-slate-900/40 text-[10px] font-mono rounded-lg text-slate-300 cursor-pointer"
                  >
                    Copy MD
                  </button>
                  <button
                    onClick={() => {
                      const md = generateMarkdownReport(activeScanResult, repoResult?.repo, repoResult?.branch);
                      handleDownloadFile("patchpilot-security-report.md", md);
                    }}
                    className="px-3 py-1.5 border border-slate-800 hover:border-slate-700 bg-slate-900/40 text-[10px] font-mono rounded-lg text-slate-300 cursor-pointer"
                  >
                    Download MD
                  </button>
                  <button
                    onClick={() => {
                      const sarif = generateSarifReport(activeScanResult);
                      handleCopyText(sarif, "SARIF report copied to clipboard!");
                    }}
                    className="px-3 py-1.5 border border-slate-800 hover:border-slate-700 bg-slate-900/40 text-[10px] font-mono rounded-lg text-slate-300 cursor-pointer"
                  >
                    Copy SARIF
                  </button>
                  <button
                    onClick={() => {
                      const sarif = generateSarifReport(activeScanResult);
                      handleDownloadFile("patchpilot-sarif.json", sarif);
                    }}
                    className="px-3 py-1.5 border border-slate-800 hover:border-slate-700 bg-slate-900/40 text-[10px] font-mono rounded-lg text-slate-300 cursor-pointer"
                  >
                    Download SARIF
                  </button>
                  <button
                    onClick={() => {
                      handleCopyText(JSON.stringify(activeScanResult, null, 2), "Redacted JSON copied to clipboard!");
                    }}
                    className="px-3 py-1.5 border border-slate-800 hover:border-slate-700 bg-slate-900/40 text-[10px] font-mono rounded-lg text-slate-300 cursor-pointer"
                  >
                    Copy JSON
                  </button>
                </div>

                {/* Editor Findings Deck List */}
                {activeTab !== "github-repo" && (
                  <>
                    {activeScanResult.findings.length > 0 ? (
                      <div className="space-y-2">
                        <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wide">Findings Detected ({activeScanResult.findings.length})</div>
                        <div className="max-h-[220px] overflow-y-auto space-y-2 pr-1">
                          {activeScanResult.findings.map((finding: Finding) => (
                            <div
                              key={finding.id}
                              onClick={() => setSelectedFindingId(finding.id)}
                              className={`p-3 border rounded-xl cursor-pointer transition-all flex items-start justify-between ${
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
                        <span className="text-xs text-slate-400 font-mono">All checks passed. Codebase secure!</span>
                      </div>
                    )}
                  </>
                )}

                {/* Selected Finding Detail Board */}
                {selectedFinding && (
                  <div className="border border-slate-900 rounded-2xl p-5 bg-slate-900/40 space-y-4 backdrop-blur-sm animate-fadeIn">
                    
                    {/* Header line */}
                    <div className="flex items-center justify-between pb-3 border-b border-slate-900">
                      <div>
                        <h3 className="text-sm font-bold text-white">{selectedFinding.title}</h3>
                        <div className="flex items-center space-x-2 text-[10px] font-mono text-slate-500 uppercase tracking-wide mt-0.5">
                          <span>{selectedFinding.cwe}</span>
                          <span>&bull;</span>
                          <span>{selectedFinding.owasp}</span>
                        </div>
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

                    {/* Meta Indicators */}
                    <div className="grid grid-cols-2 gap-2 text-[10px] font-mono bg-slate-950/40 p-2.5 rounded-lg border border-slate-900/60">
                      <div><span className="text-slate-500">Confidence:</span> <span className="text-slate-300 font-bold capitalize">{selectedFinding.confidence}</span></div>
                      <div><span className="text-slate-500">Line Range:</span> <span className="text-slate-300">{selectedFinding.lineStart}-{selectedFinding.lineEnd}</span></div>
                      <div className="col-span-2"><span className="text-slate-500">Matched because:</span> <span className="text-slate-300 italic">{selectedFinding.matchedBecause}</span></div>
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

                    {/* Evidence */}
                    <div className="space-y-1">
                      <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wide block">Evidence (Redacted)</span>
                      <pre className="font-mono text-xs text-red-300/80 bg-red-950/20 border border-red-900/35 rounded-lg p-3 overflow-x-auto leading-relaxed max-w-full">
                        <code>{selectedFinding.evidence}</code>
                      </pre>
                    </div>

                    {/* Patch Suggestion Diff */}
                    <div className="space-y-2">
                      <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wide block">Safer Patch Recommendation</span>
                      {renderDiff(selectedFinding.patch.diff)}

                      {/* Apply actions */}
                      <div className="flex items-center gap-2 pt-2">
                        {activeTab === "editor" && (
                          <button
                            onClick={() => applyFix(selectedFinding)}
                            className="flex-1 inline-flex items-center justify-center px-4 py-2.5 text-xs font-semibold text-slate-950 bg-accent hover:bg-accent-hover rounded-lg transition-colors cursor-pointer"
                          >
                            <svg className="w-4 h-4 mr-1.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                              <path strokeLinecap="round" strokeLinejoin="round" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
                            </svg>
                            Apply Fix to Editor
                          </button>
                        )}
                        <button
                          onClick={() => handleCopyText(selectedFinding.patch.after, "Safe replacement copied to clipboard!")}
                          className="px-4 py-2.5 text-xs font-semibold text-slate-200 bg-slate-900 border border-slate-800 hover:bg-slate-800 rounded-lg transition-colors cursor-pointer flex-1"
                          title="Copy safe replacement code segment"
                        >
                          Copy Safe Code
                        </button>
                      </div>
                    </div>

                    {/* AI Explanation Accordion */}
                    <div className="border-t border-slate-900 pt-4 space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wide block">AI Security Explainer Layer</span>
                        {!aiExplanation && !isAiLoading && (
                          <button
                            onClick={() => fetchAiExplanation(selectedFinding)}
                            className="text-[10px] font-mono text-accent hover:underline cursor-pointer"
                          >
                            Generate AI Explanation
                          </button>
                        )}
                      </div>

                      {isAiLoading && (
                        <div className="p-3 border border-slate-900 rounded-xl bg-slate-950/20 text-center text-xs text-slate-500 font-mono flex items-center justify-center space-x-2">
                          <div className="w-3.5 h-3.5 border-2 border-slate-500 border-t-transparent rounded-full animate-spin" />
                          <span>Generating AI Security Briefing...</span>
                        </div>
                      )}

                      {aiError && (
                        <div className="p-3 border border-red-950/40 rounded-xl bg-red-950/10 text-xs text-red-400 font-mono">
                          {aiError}
                        </div>
                      )}

                      {aiExplanation && (
                        <div className="space-y-3 bg-slate-950/40 border border-slate-900/60 p-4 rounded-xl text-xs space-y-3 leading-relaxed">
                          <div>
                            <span className="font-bold text-white block mb-0.5">Beginner Overview</span>
                            <p className="text-slate-400">{aiExplanation.beginnerExplanation}</p>
                          </div>
                          <div>
                            <span className="font-bold text-white block mb-0.5">Remediation Rationale</span>
                            <p className="text-slate-400">{aiExplanation.secureFixExplanation}</p>
                          </div>
                          <div>
                            <span className="font-bold text-white block mb-0.5">Interview-Style Answer</span>
                            <p className="text-slate-400">{aiExplanation.interviewSummary}</p>
                          </div>
                          <div>
                            <span className="font-bold text-white block mb-0.5">Caveats & Assumptions</span>
                            <p className="text-slate-400">{aiExplanation.caveats}</p>
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Rule Reference Documentation Section */}
                    {doc && (
                      <div className="border-t border-slate-900 pt-4">
                        <div
                          onClick={() => setIsDocExpanded(!isDocExpanded)}
                          className="flex items-center justify-between text-xs font-mono font-bold text-slate-500 cursor-pointer hover:text-slate-300 select-none"
                        >
                          <span>Rule Reference Documentation</span>
                          <span>{isDocExpanded ? "[-]" : "[+]"}</span>
                        </div>
                        
                        {isDocExpanded && (
                          <div className="mt-3 bg-slate-950/20 border border-slate-900/80 p-3.5 rounded-xl text-[11px] space-y-3 leading-relaxed text-slate-400">
                            <div>
                              <span className="text-slate-500 font-mono uppercase tracking-wide block text-[9px] mb-0.5">What it detects</span>
                              <p>{doc.whatItDetects}</p>
                            </div>
                            <div>
                              <span className="text-slate-500 font-mono uppercase tracking-wide block text-[9px] mb-0.5">Why it matters</span>
                              <p>{doc.whyItMatters}</p>
                            </div>
                            <div>
                              <span className="text-slate-500 font-mono uppercase tracking-wide block text-[9px] mb-0.5">Common False Positives</span>
                              <p>{doc.commonFalsePositives}</p>
                            </div>
                            <div>
                              <span className="text-slate-500 font-mono uppercase tracking-wide block text-[9px] mb-0.5">Safer Patterns</span>
                              <p className="font-mono text-slate-300">{doc.saferPatterns}</p>
                            </div>
                          </div>
                        )}
                      </div>
                    )}

                  </div>
                )}

              </div>
            )}

            {/* Static limitations footer tag */}
            <div className="border border-slate-900/50 bg-slate-950/20 rounded-2xl p-4 text-[10px] font-mono text-slate-500 leading-relaxed">
              <span className="text-slate-400 font-bold block mb-1">Scanner Warnings & Limitations:</span>
              PatchPilot is a focused static-pattern scanner, not a full compiler/AST SAST engine. Findings are deterministic and reproducible. Patch suggestions should be reviewed and approved before production use. All matching credentials and secrets are fully redacted in scanner outputs.
            </div>

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
