import { rules } from "./rules";

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
  /** The exact matching code snippet containing the vulnerability pattern */
  evidence: string;
  /** Explanation of the security vulnerability threat */
  explanation: string;
  /** Actionable guidance on how to fix the code */
  recommendation: string;
  /** Patch recommendation data */
  patch: {
    /** The code lines before modification */
    before: string;
    /** The recommended secure code lines replacement */
    after: string;
    /** A git-style unified diff representation */
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

function getLineNumbers(code: string, startIndex: number, endIndex: number) {
  const before = code.substring(0, startIndex);
  const lineStart = before.split("\n").length;
  const matchContent = code.substring(startIndex, endIndex);
  const lineEnd = lineStart + Math.max(0, matchContent.split("\n").length - 1);
  return { lineStart, lineEnd };
}

export function scanCode(code: string, language: string): ScanResult {
  const findings: Finding[] = [];
  const normalizedLang = language.toLowerCase();

  // Run through rules
  for (const rule of rules) {
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
        
        // Generate patch recommendations
        const patch = pattern.generatePatch(matchText, normalizedLang);

        findingIdx++;
        findings.push({
          id: `${rule.id}-${findingIdx}`,
          title: rule.title,
          severity: rule.severity,
          category: rule.category,
          lineStart,
          lineEnd,
          evidence: matchText,
          explanation: rule.explanation,
          recommendation: rule.recommendation,
          patch
        });
      }
    }
  }

  // Calculate score starting at 100
  let score = 100;
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;

  for (const finding of findings) {
    if (finding.severity === "critical") {
      score -= 25;
      criticalCount++;
    } else if (finding.severity === "high") {
      score -= 15;
      highCount++;
    } else if (finding.severity === "medium") {
      score -= 8;
      mediumCount++;
    } else {
      score -= 3;
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
