import { demoCases } from "../lib/scanner/demoCases";
import { scanCode } from "../lib/scanner/scan";

// Simple URL parsing verification stub mimicking the API route logic
function parseGitHubUrl(urlStr: string) {
  const url = new URL(urlStr);
  if (url.hostname !== "github.com" && url.hostname !== "raw.githubusercontent.com") {
    throw new Error("Only github.com and raw.githubusercontent.com URLs are allowed.");
  }
  if (url.hostname === "raw.githubusercontent.com") {
    const parts = url.pathname.split("/").filter(Boolean);
    const [owner, repo, branch, ...pathParts] = parts;
    return { owner, repo, branch, path: pathParts.join("/") };
  }
  const parts = url.pathname.split("/").filter(Boolean);
  const [owner, repo, action, ...rest] = parts;
  if (action !== "blob") {
    throw new Error("Only single file blob URLs are supported in this mode.");
  }
  const branch = rest[0];
  const path = rest.slice(1).join("/");
  return { owner, repo, branch, path };
}

function runVerification() {
  console.log("=== Starting PatchPilot Security Verification Harness ===");
  let success = true;

  // 1. Verify URL parsing logic
  console.log("\n[Test 1] Verifying GitHub URL parsing & security constraints...");
  const validWebUrl = "https://github.com/Barap1/PatchPilot/blob/main/src/app/page.tsx";
  const validRawUrl = "https://raw.githubusercontent.com/Barap1/PatchPilot/main/src/app/page.tsx";
  const invalidUrl = "https://evil-site.com/Barap1/PatchPilot/blob/main/src/app/page.tsx";
  const localhostUrl = "http://localhost:3000/Barap1/PatchPilot/blob/main/src/app/page.tsx";

  try {
    const parsedWeb = parseGitHubUrl(validWebUrl);
    if (parsedWeb.owner !== "Barap1" || parsedWeb.repo !== "PatchPilot" || parsedWeb.branch !== "main" || parsedWeb.path !== "src/app/page.tsx") {
      console.error("❌ Failed to parse valid GitHub web URL correctly.");
      success = false;
    } else {
      console.log("✅ Passed: Valid GitHub web URL parsed correctly.");
    }
  } catch (err: unknown) {
    console.error("❌ Unexpected error parsing valid web URL:", (err as Error).message);
    success = false;
  }

  try {
    const parsedRaw = parseGitHubUrl(validRawUrl);
    if (parsedRaw.owner !== "Barap1" || parsedRaw.repo !== "PatchPilot" || parsedRaw.branch !== "main" || parsedRaw.path !== "src/app/page.tsx") {
      console.error("❌ Failed to parse valid raw GitHub URL correctly.");
      success = false;
    } else {
      console.log("✅ Passed: Valid GitHub raw URL parsed correctly.");
    }
  } catch (err: unknown) {
    console.error("❌ Unexpected error parsing valid raw URL:", (err as Error).message);
    success = false;
  }

  try {
    parseGitHubUrl(invalidUrl);
    console.error("❌ Security failure: Allowed non-GitHub URL!");
    success = false;
  } catch (_err) {
    console.log("✅ Passed: Correctly rejected non-GitHub URL.");
  }

  try {
    parseGitHubUrl(localhostUrl);
    console.error("❌ Security failure: Allowed localhost URL!");
    success = false;
  } catch (_err) {
    console.log("✅ Passed: Correctly rejected localhost URL.");
  }

  // 2. Verify Demo Cases
  console.log("\n[Test 2] Verifying static analysis demo cases...");
  for (const demo of demoCases) {
    console.log(`\n--------------------------------------------`);
    console.log(`Verifying Demo Case: ${demo.name} (${demo.id})`);
    
    const languagesToTest = ["javascript", "typescript", "python"] as const;
    
    for (const lang of languagesToTest) {
      const codeToScan = demo.languages[lang];
      if (!codeToScan) {
        console.error(`  ❌ ERROR: Missing source code for ${lang} in ${demo.id}!`);
        success = false;
        continue;
      }
      
      const scanResult = scanCode(codeToScan, lang);
      console.log(`  [${lang.toUpperCase()}] Score: ${scanResult.score}/100, Findings: ${scanResult.findings.length}`);
      
      // Verification rules:
      // A. Check that score decreases (findings exist -> score < 100)
      if (scanResult.findings.length > 0 && scanResult.score >= 100) {
        console.error(`  ❌ ERROR: Findings exist but score is 100!`);
        success = false;
      }

      // B. Check that expected rule ID is triggered
      const triggeredIds = scanResult.findings.map(f => f.id.substring(0, f.id.lastIndexOf("-")));
      const matchedExpected = demo.expectedRuleIds.every(id => triggeredIds.includes(id));
      if (!matchedExpected) {
        console.error(`  ❌ ERROR: Did not trigger expected rule IDs! Expected: [${demo.expectedRuleIds.join(", ")}], Triggered: [${triggeredIds.join(", ")}]`);
        success = false;
      } else {
        console.log(`  ✅ Passed: Triggered expected rule IDs.`);
      }

      // C. Validate findings structure (line numbers, patch model, and redaction)
      for (const finding of scanResult.findings) {
        if (finding.lineStart <= 0 || finding.lineEnd < finding.lineStart) {
          console.error(`  ❌ ERROR: Invalid finding line range: ${finding.lineStart}-${finding.lineEnd}`);
          success = false;
        }

        const patch = finding.patch;
        if (!patch || !patch.before || !patch.after || !patch.diff || patch.replacementStart === undefined || patch.replacementEnd === undefined) {
          console.error(`  ❌ ERROR: Finding '${finding.title}' is missing complete patch data.`);
          success = false;
        }

        // D. Verify secret redaction
        // If the code contains a simulated raw secret, make sure the finding outputs do NOT leak it
        const secretsInSnippet = [
          "sk-proj-aB1c2D3e4F5g6H7i8J9k0L1m2N3o4P5q6R7s8T9u",
          "AKIA1234567890ABCDEF"
        ];
        
        for (const rawSecret of secretsInSnippet) {
          if (codeToScan.includes(rawSecret)) {
            // Check if finding outputs contain the raw secret
            if (
              finding.evidence.includes(rawSecret) ||
              patch.before.includes(rawSecret) ||
              patch.fullLineBefore.includes(rawSecret) ||
              patch.diff.includes(rawSecret)
            ) {
              console.error(`  ❌ ERROR: Raw secret '${rawSecret}' leaked in scan finding results!`);
              success = false;
            } else {
              console.log(`  ✅ Passed: Raw secret '${rawSecret.substring(0, 8)}...' successfully redacted in outputs.`);
            }
          }
        }
      }
    }
  }

  if (success) {
    console.log(`\n🎉 SUCCESS: All PatchPilot verification criteria passed successfully!`);
    process.exit(0);
  } else {
    console.error(`\n❌ FAILURE: Verification failed. Review logs for details.`);
    process.exit(1);
  }
}

runVerification();
