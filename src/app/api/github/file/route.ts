import { NextRequest, NextResponse } from "next/server";

export const dynamic = "force-dynamic";

/**
 * Normalizes and parses a GitHub file URL or raw file URL.
 */
function parseGitHubUrl(urlStr: string) {
  const url = new URL(urlStr);
  if (url.hostname !== "github.com" && url.hostname !== "raw.githubusercontent.com") {
    throw new Error("Only github.com and raw.githubusercontent.com URLs are allowed.");
  }

  // Parse raw URL: https://raw.githubusercontent.com/owner/repo/branch/path/to/file.ts
  if (url.hostname === "raw.githubusercontent.com") {
    const parts = url.pathname.split("/").filter(Boolean);
    if (parts.length < 4) {
      throw new Error("Invalid GitHub raw URL format.");
    }
    const [owner, repo, branch, ...pathParts] = parts;
    const path = pathParts.join("/");
    return { owner, repo, branch, path, rawUrl: urlStr };
  }

  // Parse web URL: https://github.com/owner/repo/blob/branch/path/to/file.ts
  const parts = url.pathname.split("/").filter(Boolean);
  if (parts.length < 4) {
    throw new Error("Invalid GitHub URL format.");
  }
  const [owner, repo, action, ...rest] = parts;
  if (action !== "blob") {
    throw new Error("Only single file blob URLs are supported in this mode.");
  }
  const branch = rest[0];
  const path = rest.slice(1).join("/");
  const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${path}`;
  return { owner, repo, branch, path, rawUrl };
}

/**
 * Infers programming language from file extension.
 */
function inferLanguageFromExtension(path: string): string {
  const ext = path.split(".").pop()?.toLowerCase();
  if (ext === "js" || ext === "jsx") return "javascript";
  if (ext === "ts" || ext === "tsx") return "typescript";
  if (ext === "py") return "python";
  throw new Error(`Unsupported file extension: .${ext}. Only .js, .jsx, .ts, .tsx, and .py files are supported.`);
}

/**
 * POST /api/github/file
 * Body: { url: string }
 */
export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { url } = body;

    if (!url || typeof url !== "string") {
      return NextResponse.json({ error: "Missing or invalid 'url' field." }, { status: 400 });
    }

    let parsed;
    try {
      parsed = parseGitHubUrl(url.trim());
    } catch (err: any) {
      return NextResponse.json({ error: err.message || "Failed to parse GitHub URL." }, { status: 400 });
    }

    let language;
    try {
      language = inferLanguageFromExtension(parsed.path);
    } catch (err: any) {
      return NextResponse.json({ error: err.message }, { status: 400 });
    }

    // Set up 5s timeout fetch
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    try {
      const response = await fetch(parsed.rawUrl, {
        signal: controller.signal,
        headers: {
          "User-Agent": "PatchPilot-Scanner"
        }
      });
      clearTimeout(timeoutId);

      if (!response.ok) {
        return NextResponse.json({ error: `Failed to fetch file from GitHub. Status code: ${response.status}` }, { status: response.status });
      }

      // Check content-length if available (limit to 1MB)
      const contentLengthStr = response.headers.get("content-length");
      if (contentLengthStr) {
        const contentLength = parseInt(contentLengthStr, 10);
        if (contentLength > 1024 * 1024) {
          return NextResponse.json({ error: "File exceeds max allowed size of 1MB." }, { status: 400 });
        }
      }

      const code = await response.text();
      
      // Secondary check on actual content size
      if (Buffer.byteLength(code, "utf8") > 1024 * 1024) {
        return NextResponse.json({ error: "File exceeds max allowed size of 1MB." }, { status: 400 });
      }

      return NextResponse.json({
        owner: parsed.owner,
        repo: parsed.repo,
        branch: parsed.branch,
        path: parsed.path,
        language,
        code,
        sourceUrl: url
      });
    } catch (fetchErr: any) {
      clearTimeout(timeoutId);
      if (fetchErr.name === "AbortError") {
        return NextResponse.json({ error: "Fetch request to GitHub timed out (5s limit)." }, { status: 504 });
      }
      throw fetchErr;
    }
  } catch (err: any) {
    return NextResponse.json({ error: err.message || "An unexpected error occurred." }, { status: 500 });
  }
}
