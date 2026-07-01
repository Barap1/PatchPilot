import { NextRequest, NextResponse } from "next/server";
import { scanCode } from "../../../../../lib/scanner/scan";

export const dynamic = "force-dynamic";

/**
 * Infers programming language from file extension.
 */
function inferLanguageFromExtension(path: string): string | null {
  const ext = path.split(".").pop()?.toLowerCase();
  if (ext === "js" || ext === "jsx") return "javascript";
  if (ext === "ts" || ext === "tsx") return "typescript";
  if (ext === "py") return "python";
  return null;
}

/**
 * Check if a path should be excluded from scanning.
 */
function isExcludedPath(path: string): boolean {
  const segments = path.toLowerCase().split("/");
  const excludedDirs = ["node_modules", ".next", "dist", "build", ".venv", "venv", "coverage", ".git"];
  
  // Check if any segment is an excluded directory
  if (segments.some(seg => excludedDirs.includes(seg))) {
    return true;
  }

  // Check if it is a lock file or minified file
  const filename = segments[segments.length - 1];
  if (
    filename.endsWith(".lock") ||
    filename.includes("package-lock") ||
    filename.includes("yarn.lock") ||
    filename.includes("pnpm-lock") ||
    filename.endsWith(".min.js") ||
    filename.endsWith(".min.css")
  ) {
    return true;
  }

  return false;
}

interface TreeItem {
  path: string;
  type: string;
  size?: number;
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { repoUrl, branch = "main" } = body;

    if (!repoUrl || typeof repoUrl !== "string") {
      return NextResponse.json({ error: "Missing or invalid 'repoUrl' field." }, { status: 400 });
    }

    let owner = "";
    let repo = "";
    try {
      const url = new URL(repoUrl.trim());
      if (url.hostname !== "github.com") {
        return NextResponse.json({ error: "Only github.com repositories are allowed." }, { status: 400 });
      }
      const parts = url.pathname.split("/").filter(Boolean);
      if (parts.length < 2) {
        return NextResponse.json({ error: "Invalid GitHub repository URL." }, { status: 400 });
      }
      owner = parts[0];
      repo = parts[1].replace(/\.git$/, "");
    } catch (err: any) {
      return NextResponse.json({ error: "Invalid GitHub repository URL format." }, { status: 400 });
    }

    const targetBranch = branch.trim() || "main";

    // 1. Fetch public git tree recursive
    const treeApiUrl = `https://api.github.com/repos/${owner}/${repo}/git/trees/${targetBranch}?recursive=1`;
    
    const treeController = new AbortController();
    const treeTimeout = setTimeout(() => treeController.abort(), 6000);
    
    let treeResponse;
    try {
      treeResponse = await fetch(treeApiUrl, {
        signal: treeController.signal,
        headers: {
          "User-Agent": "PatchPilot-Scanner",
          Accept: "application/vnd.github.v3+json"
        }
      });
      clearTimeout(treeTimeout);
    } catch (err: any) {
      clearTimeout(treeTimeout);
      if (err.name === "AbortError") {
        return NextResponse.json({ error: "GitHub API request timed out (6s limit)." }, { status: 504 });
      }
      throw err;
    }

    if (!treeResponse.ok) {
      if (treeResponse.status === 403 || treeResponse.status === 429) {
        return NextResponse.json({
          error: "GitHub API rate limit exceeded or access forbidden. Please try again later."
        }, { status: treeResponse.status });
      }
      return NextResponse.json({
        error: `Failed to fetch repository tree from GitHub (status ${treeResponse.status}). Make sure the repository is public and the branch exists.`
      }, { status: treeResponse.status });
    }

    const treeData = await treeResponse.json();
    const items: TreeItem[] = treeData.tree || [];

    const filesToScan: TreeItem[] = [];
    const skippedFiles: Array<{ path: string; reason: string }> = [];

    for (const item of items) {
      if (item.type !== "blob") continue;

      if (isExcludedPath(item.path)) {
        skippedFiles.push({ path: item.path, reason: "excluded path" });
        continue;
      }

      const lang = inferLanguageFromExtension(item.path);
      if (!lang) {
        skippedFiles.push({ path: item.path, reason: "unsupported file extension" });
        continue;
      }

      // Check size (max 500KB per file)
      if (item.size && item.size > 500 * 1024) {
        skippedFiles.push({ path: item.path, reason: "file too large (>500KB)" });
        continue;
      }

      filesToScan.push(item);
    }

    // Limit to max 25 files
    const finalFilesToScan = filesToScan.slice(0, 25);
    const skippedOverLimit = filesToScan.slice(25);
    for (const item of skippedOverLimit) {
      skippedFiles.push({ path: item.path, reason: "limit exceeded (max 25 files per scan)" });
    }

    const results = [];
    let totalFindingsCount = 0;
    
    // Severity counts
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;

    // Fetch and scan files concurrently (with safety limits)
    const scanPromises = finalFilesToScan.map(async (file) => {
      const fileLang = inferLanguageFromExtension(file.path)!;
      const rawFileUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${targetBranch}/${file.path}`;
      
      const fileController = new AbortController();
      const fileTimeout = setTimeout(() => fileController.abort(), 4000);

      try {
        const fileResponse = await fetch(rawFileUrl, {
          signal: fileController.signal,
          headers: {
            "User-Agent": "PatchPilot-Scanner"
          }
        });
        clearTimeout(fileTimeout);

        if (!fileResponse.ok) {
          return { path: file.path, error: `Failed to download file content (status ${fileResponse.status})` };
        }

        const code = await fileResponse.text();
        const scanResult = scanCode(code, fileLang);

        return {
          path: file.path,
          language: fileLang,
          score: scanResult.score,
          findings: scanResult.findings
        };
      } catch (err: any) {
        clearTimeout(fileTimeout);
        return { path: file.path, error: err.message || "Failed to fetch file content." };
      }
    });

    const scanResults = await Promise.all(scanPromises);

    for (const res of scanResults) {
      if ("error" in res) {
        skippedFiles.push({ path: res.path, reason: res.error });
        continue;
      }
      results.push(res);
      totalFindingsCount += res.findings.length;
      
      for (const finding of res.findings) {
        if (finding.severity === "critical") criticalCount++;
        else if (finding.severity === "high") highCount++;
        else if (finding.severity === "medium") mediumCount++;
        else lowCount++;
      }
    }

    // Repository-wide aggregate score calculation using severity weights
    const weights = {
      critical: 25,
      high: 15,
      medium: 8,
      low: 3
    };

    let repoScore = 100;
    repoScore -= criticalCount * weights.critical;
    repoScore -= highCount * weights.high;
    repoScore -= mediumCount * weights.medium;
    repoScore -= lowCount * weights.low;
    repoScore = Math.max(0, repoScore);

    let summary = "";
    if (totalFindingsCount === 0) {
      summary = `Scan of repository '${owner}/${repo}' on branch '${targetBranch}' completed. No vulnerability patterns detected across ${results.length} files.`;
    } else {
      const parts: string[] = [];
      if (criticalCount > 0) parts.push(`${criticalCount} critical`);
      if (highCount > 0) parts.push(`${highCount} high`);
      if (mediumCount > 0) parts.push(`${mediumCount} medium`);
      if (lowCount > 0) parts.push(`${lowCount} low`);
      summary = `Scan of repository '${owner}/${repo}' on branch '${targetBranch}' completed with ${totalFindingsCount} findings across ${results.length} scanned files (${parts.join(", ")}). Aggregate score is ${repoScore}/100.`;
    }

    return NextResponse.json({
      repo: `${owner}/${repo}`,
      branch: targetBranch,
      filesScanned: results.length,
      filesSkipped: skippedFiles.length,
      score: repoScore,
      summary,
      results,
      skipped: skippedFiles
    });
  } catch (err: any) {
    return NextResponse.json({ error: err.message || "An unexpected error occurred during repository scanning." }, { status: 500 });
  }
}
