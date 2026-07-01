import { NextRequest, NextResponse } from "next/server";
import { redactSecrets } from "../../../../lib/scanner/redaction";

export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  try {
    const apiKey = process.env.OPENAI_API_KEY;
    if (!apiKey) {
      return NextResponse.json({
        error: "AI explanation not configured. Please set the OPENAI_API_KEY environment variable."
      }, { status: 400 });
    }

    const body = await req.json();
    const { finding, codeContext } = body;

    if (!finding) {
      return NextResponse.json({ error: "Missing 'finding' payload." }, { status: 400 });
    }

    // Run redaction on codeContext just in case it contains secrets
    const redactedContext = redactSecrets(codeContext || "");

    const prompt = `You are a security expert. Analyze the following static analysis finding and code context:
    
Vulnerability Title: ${finding.title}
Category: ${finding.category}
CWE: ${finding.cwe}
OWASP: ${finding.owasp}
Severity: ${finding.severity}
Matched because: ${finding.matchedBecause}

Redacted Evidence:
\`\`\`
${finding.evidence}
\`\`\`

Redacted Surrounding Code Context:
\`\`\`
${redactedContext}
\`\`\`

Generate a clean explanation package containing:
1. Beginner Explanation: A simple, non-jargon explanation of what the vulnerability is.
2. Secure Fix Explanation: How the patch solves it and why it's secure.
3. Interview Summary: A high-level technical summary perfect for a job interview.
4. Caveats: Common false positives, assumptions, or alternative patterns.

Your response must be JSON only. Return exactly this JSON schema (do not write markdown backticks or explanations outside the JSON):
{
  "beginnerExplanation": "...",
  "secureFixExplanation": "...",
  "interviewSummary": "...",
  "caveats": "..."
}`;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000); // 10s timeout

    try {
      const response = await fetch("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        signal: controller.signal,
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${apiKey}`
        },
        body: JSON.stringify({
          model: "gpt-4o-mini",
          messages: [
            { role: "system", content: "You are a helpful security expert. You always output responses in raw JSON matching the requested structure." },
            { role: "user", content: prompt }
          ],
          response_format: { type: "json_object" },
          temperature: 0.2
        })
      });
      clearTimeout(timeoutId);

      if (!response.ok) {
        return NextResponse.json({ error: `OpenAI API returned error status ${response.status}.` }, { status: 502 });
      }

      const openAiData = await response.json();
      const content = openAiData.choices?.[0]?.message?.content;
      if (!content) {
        return NextResponse.json({ error: "Empty explanation returned from AI." }, { status: 500 });
      }

      const parsedContent = JSON.parse(content);
      return NextResponse.json(parsedContent);
    } catch (apiErr: unknown) {
      clearTimeout(timeoutId);
      if (apiErr && typeof apiErr === "object" && "name" in apiErr && apiErr.name === "AbortError") {
        return NextResponse.json({ error: "OpenAI request timed out." }, { status: 504 });
      }
      throw apiErr;
    }
  } catch (err: unknown) {
    return NextResponse.json({ error: (err as Error).message || "An unexpected error occurred during AI explanation." }, { status: 500 });
  }
}
