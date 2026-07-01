import { NextRequest, NextResponse } from "next/server";
import { scanCode } from "../../../../lib/scanner/scan";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { language, code } = body;

    if (code === undefined || code === null || typeof code !== "string") {
      return NextResponse.json(
        { error: "Missing or invalid 'code' field. It must be a string." },
        { status: 400 }
      );
    }

    if (!language || typeof language !== "string") {
      return NextResponse.json(
        { error: "Missing or invalid 'language' field. It must be 'javascript', 'typescript', or 'python'." },
        { status: 400 }
      );
    }

    const normalizedLang = language.toLowerCase();
    if (!["javascript", "typescript", "python"].includes(normalizedLang)) {
      return NextResponse.json(
        { error: "Unsupported language. Must be 'javascript', 'typescript', or 'python'." },
        { status: 400 }
      );
    }

    const result = scanCode(code, normalizedLang);
    return NextResponse.json(result);
  } catch (err: any) {
    return NextResponse.json(
      { error: err.message || "An unexpected error occurred during code scanning." },
      { status: 500 }
    );
  }
}
