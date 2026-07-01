import { demoCases } from "../lib/scanner/demoCases";
import { scanCode } from "../lib/scanner/scan";

function runVerification() {
  console.log("Starting verification of PatchPilot demo cases...");
  let success = true;

  for (const demo of demoCases) {
    console.log(`\n--------------------------------------------`);
    console.log(`Verifying Case: ${demo.name} (${demo.id})`);
    
    // Test JS
    const jsResult = scanCode(demo.languages.javascript, "javascript");
    console.log(`  [JS] Score: ${jsResult.score}, Findings: ${jsResult.findings.length}`);
    if (jsResult.findings.length === 0) {
      console.error(`  ❌ ERROR: No findings for Javascript demo!`);
      success = false;
    } else {
      console.log(`  ✅ Passed: found ${jsResult.findings[0].title} on lines ${jsResult.findings[0].lineStart}-${jsResult.findings[0].lineEnd}`);
    }

    // Test TS
    const tsResult = scanCode(demo.languages.typescript, "typescript");
    console.log(`  [TS] Score: ${tsResult.score}, Findings: ${tsResult.findings.length}`);
    if (tsResult.findings.length === 0) {
      console.error(`  ❌ ERROR: No findings for TypeScript demo!`);
      success = false;
    } else {
      console.log(`  ✅ Passed: found ${tsResult.findings[0].title} on lines ${tsResult.findings[0].lineStart}-${tsResult.findings[0].lineEnd}`);
    }

    // Test Python
    const pyResult = scanCode(demo.languages.python, "python");
    console.log(`  [Py] Score: ${pyResult.score}, Findings: ${pyResult.findings.length}`);
    if (pyResult.findings.length === 0) {
      console.error(`  ❌ ERROR: No findings for Python demo!`);
      success = false;
    } else {
      console.log(`  ✅ Passed: found ${pyResult.findings[0].title} on lines ${pyResult.findings[0].lineStart}-${pyResult.findings[0].lineEnd}`);
    }
  }

  if (success) {
    console.log(`\n🎉 SUCCESS: All demo cases successfully triggered expected vulnerabilities!`);
    process.exit(0);
  } else {
    console.log(`\n❌ FAILURE: Some demo cases did not trigger expected vulnerabilities.`);
    process.exit(1);
  }
}

runVerification();
