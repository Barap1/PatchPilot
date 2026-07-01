import { NextRequest, NextResponse } from "next/server";
import { scanCode } from "../../../../lib/scanner/scan";

/**
 * POST /api/scan
 * Receives code and target programming language, runs static static scanning,
 * and returns findings and calculated security score.
 */
export async function POST(req: NextRequest) {
  try {
    // Parse JSON request body
    const body = await req.json();
    const { language, code } = body;

    // Validate the presence and type of 'code' parameter
    if (code === undefined || code === null || typeof code !== "string") {
      return NextResponse.json(
        { error: "Missing or invalid 'code' field. It must be a string." },
        { status: 400 }
      );
    }

    // Validate the presence and type of 'language' parameter
    if (!language || typeof language !== "string") {
      return NextResponse.json(
        { error: "Missing or invalid 'language' field. It must be 'javascript', 'typescript', or 'python'." },
        { status: 400 }
      );
    }

    // Normalize and verify supported target languages
    const normalizedLang = language.toLowerCase();
    if (!["javascript", "typescript", "python"].includes(normalizedLang)) {
      return NextResponse.json(
        { error: "Unsupported language. Must be 'javascript', 'typescript', or 'python'." },
        { status: 400 }
      );
    }

    // Invoke deterministic scanner coordinator
    const result = scanCode(code, normalizedLang);
    return NextResponse.json(result);
  } catch (err: unknown) {
    // Return standard error payload in case of unhandled JSON parses or scanner engine exceptions
    return NextResponse.json(
      { error: (err as Error).message || "An unexpected error occurred during code scanning." },
      { status: 500 }
    );
  }
}
