/**
 * Represents a security vulnerability rule used by the static scanner.
 */
export interface Rule {
  /** Unique string identifier for the rule */
  id: string;
  /** Human-readable title of the rule */
  title: string;
  /** Severity level rating of the rule findings */
  severity: "low" | "medium" | "high" | "critical";
  /** Categorization label for grouping findings */
  category: string;
  /** Detailed description of the risk associated with this rule */
  explanation: string;
  /** Step-by-step guidance on how to fix the vulnerability */
  recommendation: string;
  /** Common Weakness Enumeration ID */
  cwe: string;
  /** OWASP Top 10 Category ID */
  owasp: string;
  /** Detection confidence rating */
  confidence: "low" | "medium" | "high";
  /** Target programming languages supported by this rule */
  languages: Array<"javascript" | "typescript" | "python">;
  /** The regex patterns and patch builders for detecting this rule */
  patterns: Array<{
    regex: RegExp;
    replacementMode: "range" | "line";
    matchedBecause: string;
    generatePatch: (match: string, language: string) => { before: string; after: string; diff: string };
  }>;
}

// Helper to format clean diff blocks
function makeDiff(before: string, after: string): string {
  return `@@ -1,1 +1,1 @@\n-${before}\n+${after}`;
}

export const rules: Rule[] = [
  {
    id: "hardcoded-secrets",
    title: "Hardcoded Secret / API Key",
    severity: "critical",
    category: "Secrets Management",
    explanation: "Sensitive credentials such as API keys, tokens, or private keys are hardcoded in the source code. If the repository is exposed or shared, these secrets can be leaked, leading to unauthorized access and potential compromise of services.",
    recommendation: "Remove the hardcoded secret. Store it in environment variables (e.g., using process.env in Node.js or os.environ in Python) or use a dedicated secrets manager.",
    cwe: "CWE-798",
    owasp: "A07:2021 Identification and Authentication Failures",
    confidence: "high",
    languages: ["javascript", "typescript", "python"],
    patterns: [
      {
        // OpenAI/general sk- keys (supporting hyphens)
        regex: /sk-[a-zA-Z0-9-]{20,}/g,
        replacementMode: "range",
        matchedBecause: "Matched because a hardcoded OpenAI-style API key (sk-...) was detected.",
        generatePatch: (match, lang) => {
          const isPy = lang === "python";
          const replacement = isPy ? "os.environ.get('API_KEY')" : "process.env.API_KEY";
          return {
            before: match,
            after: replacement,
            diff: makeDiff(match, replacement)
          };
        }
      },
      {
        // AWS Access Key ID
        regex: /\bAKIA[A-Z0-9]{16}\b/g,
        replacementMode: "range",
        matchedBecause: "Matched because a hardcoded AWS Access Key ID (AKIA...) was detected.",
        generatePatch: (match, lang) => {
          const isPy = lang === "python";
          const replacement = isPy ? "os.environ.get('AWS_ACCESS_KEY_ID')" : "process.env.AWS_ACCESS_KEY_ID";
          return {
            before: match,
            after: replacement,
            diff: makeDiff(match, replacement)
          };
        }
      },
      {
        // Assignment to secret/token/password (supporting typescript type syntax)
        regex: /\b(secret|token|password|api_key|apikey|private_key)\b(?:\s*:\s*[\w<>|[\]]+)?\s*[:=]\s*(["'])([^"'\r\n]{6,})\2/gi,
        replacementMode: "line",
        matchedBecause: "Matched because a variable assigned a hardcoded secret string value was detected.",
        generatePatch: (match, lang) => {
          const isPy = lang === "python";
          const parts = match.match(/\b(secret|token|password|api_key|apikey|private_key)\b/i);
          const varName = parts ? parts[1] : "SECRET";
          const envName = varName.toUpperCase();
          const replacement = isPy 
            ? `${varName} = os.environ.get('${envName}')` 
            : `const ${varName} = process.env.${envName};`;
          return {
            before: match,
            after: replacement,
            diff: makeDiff(match, replacement)
          };
        }
      }
    ]
  },
  {
    id: "sql-injection",
    title: "SQL Injection Vulnerability",
    severity: "critical",
    category: "Injection",
    explanation: "Dynamic SQL queries built using string concatenation, template literals, or formatting can be manipulated by attackers to execute arbitrary SQL commands. This bypasses authentication and allows unauthorized access to, or modification of, the database.",
    recommendation: "Use parameterized queries, prepared statements, or object-relational mapping (ORM) libraries. Never interpolate user-controlled inputs directly into SQL strings.",
    cwe: "CWE-89",
    owasp: "A03:2021 Injection",
    confidence: "high",
    languages: ["javascript", "typescript", "python"],
    patterns: [
      {
        // JS/TS template literals with interpolation
        regex: /(?:SELECT|INSERT|UPDATE|DELETE)\b[^`]*?\$\{.+?\}/gi,
        replacementMode: "range",
        matchedBecause: "Matched because user-controlled input appears to be interpolated into a SQL template query string.",
        generatePatch: (match, _lang) => {
          const before = match;
          const after = match.replace(/\$\{(.+?)\}/g, "?");
          return {
            before,
            after: `${after} /* Use parameterized values in query execution */`,
            diff: makeDiff(before, `${after} /* Use parameterized values */`)
          };
        }
      },
      {
        // JS/TS string concatenation
        regex: /(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*?["']\s*\+\s*[^"'\s]+|\w+\s*\+\s*["']\s*(?:SELECT|INSERT|UPDATE|DELETE)\b/gi,
        replacementMode: "range",
        matchedBecause: "Matched because string concatenation was used to construct a dynamic SQL query.",
        generatePatch: (match, _lang) => {
          const before = match;
          const after = match.replace(/["']\s*\+\s*\w+|\w+\s*\+\s*["']/g, "?");
          return {
            before,
            after: `${after} /* Use prepared statements */`,
            diff: makeDiff(before, `${after} /* Use prepared statements */`)
          };
        }
      },
      {
        // Python f-strings or % formatting
        regex: /f["'](?:SELECT|INSERT|UPDATE|DELETE)\b.*?\{.+?\}/gi,
        replacementMode: "range",
        matchedBecause: "Matched because Python f-string formatting was used to interpolate values directly into a SQL query.",
        generatePatch: (match, _lang) => {
          const before = match;
          const after = match.replace(/\{.+?\}/g, "%s").replace(/^f/, "");
          return {
            before,
            after: `${after} # Execute query with params tuple`,
            diff: makeDiff(before, `${after} # Use params tuple`)
          };
        }
      }
    ]
  },
  {
    id: "command-injection",
    title: "Command Injection Vulnerability",
    severity: "critical",
    category: "Injection",
    explanation: "Passing unsanitized user inputs or dynamically concatenated strings to system shell execution commands allows attackers to execute arbitrary commands on the host operating system.",
    recommendation: "Avoid running shell commands directly with user input. If necessary, use API functions that execute commands with an argument list rather than a raw shell string, and sanitize inputs strictly.",
    cwe: "CWE-78",
    owasp: "A03:2021 Injection",
    confidence: "high",
    languages: ["javascript", "typescript", "python"],
    patterns: [
      {
        // JS exec with concatenation or template literals
        regex: /\bexec\s*\(\s*(?:`[^`]*\$\{.+?\}[^`]*`|["'][^"']*(?:["']\s*\+\s*[\w.]+|[\w.]+\s*\+\s*["'])[^"']*)\s*(?:,)?/gi,
        replacementMode: "range",
        matchedBecause: "Matched because user-controlled strings are executed dynamically via a system shell.",
        generatePatch: (match, _lang) => {
          const hasComma = match.endsWith(",");
          const replacement = `execFile('ping', ['-c', '1', host]${hasComma ? "," : ""}`;
          return {
            before: match,
            after: replacement,
            diff: makeDiff(match, replacement)
          };
        }
      },
      {
        // Python subprocess/system with shell=True and dynamic variables
        regex: /\b(?:os\.system|subprocess\.run|subprocess\.Popen)\s*\(\s*(?:f["'][^"']*(?:\{.+?\})[^"']*["']|["'][^"']*(?:["']\s*\+\s*[\w.]+|[\w.]+\s*\+\s*["'])|[^,]+?\+[^,]+?)\s*(?:,\s*shell\s*=\s*True)?\s*\)/gi,
        replacementMode: "range",
        matchedBecause: "Matched because system execution command is called with dynamic inputs and shell=True.",
        generatePatch: (match, _lang) => {
          const before = match;
          const after = "subprocess.run(['ping', '-c', '1', ip], shell=False)";
          return {
            before,
            after,
            diff: makeDiff(before, after)
          };
        }
      }
    ]
  },
  {
    id: "unsafe-eval",
    title: "Unsafe Eval / Dynamic Code Execution",
    severity: "high",
    category: "RCE",
    explanation: "Using eval() or new Function() to execute strings as code allows remote code execution (RCE) if any part of the string is influenced by an attacker. This is extremely high risk and bypasses language safety boundaries.",
    recommendation: "Avoid using eval() or dynamic Function constructors. Parse structured data using JSON.parse() or use safe lookup tables and pre-defined functions instead.",
    cwe: "CWE-94",
    owasp: "A03:2021 Injection",
    confidence: "high",
    languages: ["javascript", "typescript", "python"],
    patterns: [
      {
        regex: /\beval\s*\([^)]+\)/gi,
        replacementMode: "range",
        matchedBecause: "Matched because eval() executes strings as code, bypassing safety layers.",
        generatePatch: (match, lang) => {
          const before = match;
          const after = lang === "python" ? "json.loads(user_input)" : "JSON.parse(userInput)";
          return {
            before,
            after: `${after} /* Safe alternative for JSON evaluation */`,
            diff: makeDiff(before, `${after} /* Safe JSON parse */`)
          };
        }
      },
      {
        regex: /\bnew\s+Function\s*\([^)]+\)/gi,
        replacementMode: "range",
        matchedBecause: "Matched because new Function(...) was used to dynamically compile strings.",
        generatePatch: (match, _lang) => {
          const before = match;
          const after = "/* Avoid dynamic function generation; invoke pre-defined handlers instead */";
          return {
            before,
            after,
            diff: makeDiff(before, after)
          };
        }
      }
    ]
  },
  {
    id: "insecure-cors",
    title: "Insecure CORS Policy",
    severity: "high",
    category: "Network Security",
    explanation: "Allowing all origins ('*') while enabling credentials allows malicious websites to perform cross-origin requests, access sensitive session cookies, and steal private data on behalf of authenticated users.",
    recommendation: "Do not use origin: '*' with credentials: true. Instead, specify a whitelist of trusted domain origins or validate the request origin dynamically.",
    cwe: "CWE-942",
    owasp: "A05:2021 Security Misconfiguration",
    confidence: "medium",
    languages: ["javascript", "typescript", "python"],
    patterns: [
      {
        // origin: '*' along with credentials: true
        regex: /(?:origin[s]?|["']origin[s]?["'])\s*[:=]\s*["']\*["'][\s\S]{0,100}?(?:credential[s]?|supports_credentials)\s*[:=]\s*(?:true|True)/gi,
        replacementMode: "range",
        matchedBecause: "Matched because CORS configuration enables credentials access while allowing all origins (*).",
        generatePatch: (match, _lang) => {
          const before = match;
          const after = match.replace(/["']\*["']/i, "['https://trustedapp.com']");
          return {
            before,
            after,
            diff: makeDiff(before, after)
          };
        }
      },
      {
        // Reverse order credentials first
        regex: /(?:credential[s]?|supports_credentials)\s*[:=]\s*(?:true|True)[\s\S]{0,100}?(?:origin[s]?|["']origin[s]?["'])\s*[:=]\s*["']\*["']/gi,
        replacementMode: "range",
        matchedBecause: "Matched because CORS configuration enables credentials access while allowing all origins (*).",
        generatePatch: (match, _lang) => {
          const before = match;
          const after = match.replace(/["']\*["']/i, "['https://trustedapp.com']");
          return {
            before,
            after,
            diff: makeDiff(before, after)
          };
        }
      }
    ]
  },
  {
    id: "path-traversal",
    title: "Path Traversal Vulnerability",
    severity: "high",
    category: "File Inclusion",
    explanation: "Constructing file paths directly from user input (like query params or route params) without sanitization allows attackers to read or write files outside the intended directory tree, exposing sensitive files like /etc/passwd.",
    recommendation: "Sanitize user inputs to remove path navigation sequences (e.g., '../'). Use path.basename() or resolve absolute paths and verify they reside within a secure base directory.",
    cwe: "CWE-22",
    owasp: "A01:2021 Broken Access Control",
    confidence: "high",
    languages: ["javascript", "typescript", "python"],
    patterns: [
      {
        // JS/TS readFile or createReadStream with dynamic parameters
        regex: /\b(?:readFile|readFileSync|createReadStream)\s*\(\s*([^)]*?(?:req\.|params\.|file\b|filename\b)[^)]*?)\)/gi,
        replacementMode: "range",
        matchedBecause: "Matched because user-controlled inputs are passed directly to file reading APIs.",
        generatePatch: (match, _lang) => {
          const matchMethod = match.match(/\b(readFileSync|readFile|createReadStream)\b/i);
          const method = matchMethod ? matchMethod[1] : "readFileSync";
          const argMatch = match.match(/\(([^)]+)\)/);
          const arg = argMatch ? argMatch[1].trim() : "file";
          const isFs = match.toLowerCase().includes("fs.");
          
          const replacement = isFs
            ? `fs.${method}(path.join(SAFE_DIR, path.basename(${arg})))`
            : `${method}(path.join(SAFE_DIR, path.basename(${arg})))`;
          return {
            before: match,
            after: replacement,
            diff: makeDiff(match, replacement)
          };
        }
      },
      {
        // Python open with dynamic parameters
        regex: /\bopen\s*\(\s*([^)]*?(?:request\.|params\.|file\b|filename\b)[^)]*?)\)/gi,
        replacementMode: "range",
        matchedBecause: "Matched because dynamic file path is open()ed without sanitization.",
        generatePatch: (match, _lang) => {
          const argMatch = match.match(/\(([^)]+)\)/);
          const arg = argMatch ? argMatch[1].trim() : "filename";
          const replacement = `open(os.path.join(SAFE_DIR, os.path.basename(${arg})))`;
          return {
            before: match,
            after: replacement,
            diff: makeDiff(match, replacement)
          };
        }
      }
    ]
  },
  {
    id: "weak-token-generation",
    title: "Cryptographically Weak Token Generation",
    severity: "medium",
    category: "Cryptography",
    explanation: "Math.random() (JavaScript) and the standard 'random' module (Python) generate pseudo-random numbers that are predictable. Using them for passwords, reset tokens, or session IDs allows attackers to guess credentials.",
    recommendation: "Use cryptographically secure random number generators (CSRNG) such as crypto.randomBytes() in Node.js or the 'secrets' module in Python.",
    cwe: "CWE-338",
    owasp: "A02:2021 Cryptographic Failures",
    confidence: "high",
    languages: ["javascript", "typescript", "python"],
    patterns: [
      {
        // JS Math.random used near keywords
        regex: /\b(?:token|session|password|reset|secret|key)\b[^=]*?=\s*[^=]*?\bMath\.random\s*\(\s*\)/gi,
        replacementMode: "line",
        matchedBecause: "Matched because Math.random() is used to generate variables named after keys/tokens.",
        generatePatch: (match, _lang) => {
          const before = match;
          const varNameMatch = match.match(/\b(token|session|password|reset|secret|key)\b/i);
          const varName = varNameMatch ? varNameMatch[1] : "token";
          const finalAfter = `const ${varName} = crypto.randomBytes(32).toString('hex'); // Secure generator`;
          return {
            before,
            after: finalAfter,
            diff: makeDiff(before, finalAfter)
          };
        }
      },
      {
        // Python random used near keywords
        regex: /\b(?:token|session|password|reset|secret|key)\b[^=]*?=\s*[^=]*?\brandom\.(?:random|randint|choice)\b/gi,
        replacementMode: "line",
        matchedBecause: "Matched because standard python random module is used to generate keys/tokens.",
        generatePatch: (match, _lang) => {
          const before = match;
          const varNameMatch = match.match(/\b(token|session|password|reset|secret|key)\b/i);
          const varName = varNameMatch ? varNameMatch[1] : "token";
          const finalAfter = `${varName} = secrets.token_hex(16) # Secure generator`;
          return {
            before,
            after: finalAfter,
            diff: makeDiff(before, finalAfter)
          };
        }
      }
    ]
  },
  {
    id: "sensitive-logging",
    title: "Sensitive Information Logging",
    severity: "medium",
    category: "Information Disclosure",
    explanation: "Logging sensitive values like passwords, api keys, or auth headers writes secrets into log files. These files are often saved in plaintext, backed up, or indexed by search systems, leaking the secrets to administrators or intruders.",
    recommendation: "Redact or mask sensitive information before writing it to logs, or remove the logs altogether in production.",
    cwe: "CWE-532",
    owasp: "A09:2021 Security Logging and Monitoring Failures",
    confidence: "medium",
    languages: ["javascript", "typescript", "python"],
    patterns: [
      {
        // JS console.log containing sensitive fields
        regex: /\bconsole\.(?:log|info|warn|error)\s*\(\s*[^)]*?\b(?:password|token|secret|api_key|apikey|authorization|auth)\b[^)]*?\)/gi,
        replacementMode: "line",
        matchedBecause: "Matched because sensitive variable names (password, token, etc.) are written directly to console logs.",
        generatePatch: (match, _lang) => {
          const before = match;
          const after = "console.log('User status updated'); // Redacted sensitive information";
          return {
            before,
            after,
            diff: makeDiff(before, after)
          };
        }
      },
      {
        // Python print or logging containing sensitive fields
        regex: /\b(?:print|logging\.(?:info|warning|error|debug|log))\s*\(\s*[^)]*?\b(?:password|token|secret|api_key|apikey|authorization|auth)\b[^)]*?\)/gi,
        replacementMode: "line",
        matchedBecause: "Matched because sensitive credentials or keys are written to output logging methods in Python.",
        generatePatch: (match, _lang) => {
          const before = match;
          const after = "logging.info('User status updated') # Redacted sensitive information";
          return {
            before,
            after,
            diff: makeDiff(before, after)
          };
        }
      }
    ]
  }
];
