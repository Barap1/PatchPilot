import { rules } from "./rules";
import { redactSecrets } from "./redaction";

/**
 * Represents a single vulnerability finding produced by the scanner.
 */
export interface Finding {
  /** Uniquely generated identifier for this specific finding instance */
  id: string;
  /** Title of the corresponding rule */
  title: string;
  /** Severity rating */
  severity: "low" | "medium" | "high" | "critical";
  /** Categorization label */
  category: string;
  /** The 1-indexed starting line number of the match */
  lineStart: number;
  /** The 1-indexed ending line number of the match */
  lineEnd: number;
  /** The exact matching code snippet containing the vulnerability pattern (redacted) */
  evidence: string;
  /** Explanation of the security vulnerability threat */
  explanation: string;
  /** Actionable guidance on how to fix the code */
  recommendation: string;
  /** CWE Identifier */
  cwe: string;
  /** OWASP Top 10 Category */
  owasp: string;
  /** Detection confidence rating */
  confidence: "low" | "medium" | "high";
  /** Specific reason why this pattern matched */
  matchedBecause: string;
  /** Patch recommendation data */
  patch: {
    /** The replacement mode for applying this patch */
    replacementMode: "range" | "line";
    /** Original code character index where replacement starts */
    replacementStart: number;
    /** Original code character index where replacement ends */
    replacementEnd: number;
    /** The full code line(s) before modification (redacted) */
    fullLineBefore: string;
    /** The full code line(s) after modification */
    fullLineAfter: string;
    /** The specific segment before modification (redacted) */
    before: string;
    /** The specific segment after modification */
    after: string;
    /** A git-style unified diff representation (redacted) */
    diff: string;
  };
}

/**
 * Represents the complete aggregate result of a code scan.
 */
export interface ScanResult {
  /** Overall computed security score from 0 (poor) to 100 (secure) */
  score: number;
  /** Language identifier utilized for scanning */
  language: string;
  /** Textual explanation summarizing overall scan conclusions */
  summary: string;
  /** Complete collection of vulnerability findings detected */
  findings: Finding[];
}

/**
 * Calculates 1-based start and end line numbers for a given character index range.
 */
function getLineNumbers(code: string, startIndex: number, endIndex: number) {
  const before = code.substring(0, startIndex);
  const lineStart = before.split("\n").length;
  const matchContent = code.substring(startIndex, endIndex);
  const lineEnd = lineStart + Math.max(0, matchContent.split("\n").length - 1);
  return { lineStart, lineEnd };
}

// Helper to format clean diff blocks
function makeDiff(before: string, after: string): string {
  return `@@ -1,1 +1,1 @@\n-${before}\n+${after}`;
}

/**
 * Core static analysis engine that scans source code for matching vulnerability rule patterns.
 * @param code - The string containing source code to be scanned
 * @param language - The target language (javascript, typescript, python)
 */
export function scanCode(code: string, language: string): ScanResult {
  const findings: Finding[] = [];
  const normalizedLang = language.toLowerCase();
  const seenFindings = new Set<string>();

  // Run through rules
  for (const rule of rules) {
    // Filter rules by target language
    if (!rule.languages.includes(normalizedLang as any)) {
      continue;
    }

    let findingIdx = 0;
    for (const pattern of rule.patterns) {
      // Reset regex state since it uses the global flag
      pattern.regex.lastIndex = 0;
      
      let match;
      while ((match = pattern.regex.exec(code)) !== null) {
        // Prevent infinite loops for zero-width matches
        if (match.index === pattern.regex.lastIndex) {
          pattern.regex.lastIndex++;
        }

        const matchText = match[0];
        const { lineStart, lineEnd } = getLineNumbers(code, match.index, match.index + matchText.length);
        
        // Suppress duplicate findings under the same rule and line range / evidence
        const redactedEvidence = redactSecrets(matchText);
        const dedupeKey = `${rule.id}:${lineStart}:${lineEnd}:${redactedEvidence}`;
        if (seenFindings.has(dedupeKey)) {
          continue;
        }
        seenFindings.add(dedupeKey);

        // Find character offset range of full lines for patch and diff calculations
        const lines = code.split("\n");
        let lineStartOffset = 0;
        for (let i = 0; i < lineStart - 1; i++) {
          lineStartOffset += lines[i].length + 1; // +1 for \n
        }
        let lineEndOffset = lineStartOffset;
        for (let i = lineStart - 1; i < lineEnd; i++) {
          lineEndOffset += lines[i].length + (i < lines.length - 1 ? 1 : 0);
        }

        // Generate patch recommendations
        const replacementMode = pattern.replacementMode || "range";
        const patchResult = pattern.generatePatch(matchText, normalizedLang);
        
        let before = patchResult.before;
        let after = patchResult.after;
        let replacementStart = match.index;
        let replacementEnd = match.index + matchText.length;

        // If replacementMode is range, check if the token is enclosed in quotes and expand
        if (replacementMode === "range") {
          if (!before.startsWith('"') && !before.startsWith("'") && !before.startsWith("`")) {
            if (match.index > 0 && match.index + matchText.length < code.length) {
              const charBefore = code[match.index - 1];
              const charAfter = code[match.index + matchText.length];
              if ((charBefore === '"' && charAfter === '"') || 
                  (charBefore === "'" && charAfter === "'") || 
                  (charBefore === "`" && charAfter === "`")) {
                replacementStart = match.index - 1;
                replacementEnd = match.index + matchText.length + 1;
                before = charBefore + before + charAfter;
              }
            }
          }
        } else if (replacementMode === "line") {
          replacementStart = lineStartOffset;
          replacementEnd = lineEndOffset;
          before = code.substring(lineStartOffset, lineEndOffset);
        }

        // Calculate full line previews
        const fullLineBefore = code.substring(lineStartOffset, lineEndOffset);
        let fullLineAfter = "";
        if (replacementMode === "range") {
          const relativeStart = replacementStart - lineStartOffset;
          const relativeEnd = replacementEnd - lineStartOffset;
          fullLineAfter = fullLineBefore.substring(0, relativeStart) + after + fullLineBefore.substring(relativeEnd);
        } else {
          fullLineAfter = after;
        }

        findingIdx++;
        findings.push({
          id: `${rule.id}-${findingIdx}`,
          title: rule.title,
          severity: rule.severity,
          category: rule.category,
          lineStart,
          lineEnd,
          evidence: redactedEvidence,
          explanation: rule.explanation,
          recommendation: rule.recommendation,
          cwe: rule.cwe,
          owasp: rule.owasp,
          confidence: rule.confidence,
          matchedBecause: pattern.matchedBecause,
          patch: {
            replacementMode,
            replacementStart,
            replacementEnd,
            fullLineBefore: redactSecrets(fullLineBefore),
            fullLineAfter,
            before: redactSecrets(before),
            after,
            diff: redactSecrets(makeDiff(before, after))
          }
        });
      }
    }
  }

  // Calculate score starting at 100 based on severity weights
  const weights = {
    critical: 25,
    high: 15,
    medium: 8,
    low: 3
  };

  let score = 100;
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;

  for (const finding of findings) {
    if (finding.severity === "critical") {
      score -= weights.critical;
      criticalCount++;
    } else if (finding.severity === "high") {
      score -= weights.high;
      highCount++;
    } else if (finding.severity === "medium") {
      score -= weights.medium;
      mediumCount++;
    } else {
      score -= weights.low;
      lowCount++;
    }
  }

  score = Math.max(0, score);

  // Generate summary
  let summary = "";
  if (findings.length === 0) {
    summary = "No vulnerability patterns detected. Code appears clean under deterministic scanning rules.";
  } else {
    const parts: string[] = [];
    if (criticalCount > 0) parts.push(`${criticalCount} critical`);
    if (highCount > 0) parts.push(`${highCount} high`);
    if (mediumCount > 0) parts.push(`${mediumCount} medium`);
    if (lowCount > 0) parts.push(`${lowCount} low`);
    
    summary = `Scan completed with ${findings.length} findings (${parts.join(", ")}). Security score is ${score}/100.`;
  }

  // Sort findings by line number for structured output
  findings.sort((a, b) => a.lineStart - b.lineStart);

  return {
    score,
    language,
    summary,
    findings
  };
}
