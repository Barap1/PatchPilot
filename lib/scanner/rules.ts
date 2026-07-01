export interface Rule {
  id: string;
  title: string;
  severity: "low" | "medium" | "high" | "critical";
  category: string;
  explanation: string;
  recommendation: string;
  patterns: Array<{
    regex: RegExp;
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
    patterns: [
      {
        // OpenAI/general sk- keys
        regex: /sk-[a-zA-Z0-9]{20,}/g,
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
        // Assignment to secret/token/password
        regex: /\b(secret|token|password|api_key|apikey|private_key)\b\s*[:=]\s*["']([^"'\r\n]{6,})["']/gi,
        generatePatch: (match, lang) => {
          const isPy = lang === "python";
          // Try to extract variable name and quote type
          const parts = match.match(/\b(secret|token|password|api_key|apikey|private_key)\b\s*[:=]/i);
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
    patterns: [
      {
        // JS/TS template literals with interpolation
        regex: /(?:SELECT|INSERT|UPDATE|DELETE)\b[^`]*?\$\{.+?\}/gi,
        generatePatch: (match, lang) => {
          const before = match;
          const after = match.replace(/\$\{(.+?)\}/g, "?");
          return {
            before,
            after: `${after} // Use parameterized values in query execution`,
            diff: makeDiff(before, `${after} // Use parameterized values`)
          };
        }
      },
      {
        // JS/TS string concatenation
        regex: /(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*?["']\s*\+\s*[^"'\s]+|\w+\s*\+\s*["']\s*(?:SELECT|INSERT|UPDATE|DELETE)\b/gi,
        generatePatch: (match, lang) => {
          const before = match;
          const after = match.replace(/["']\s*\+\s*\w+|\w+\s*\+\s*["']/g, "?");
          return {
            before,
            after: `${after} // Use prepared statements`,
            diff: makeDiff(before, `${after} // Use prepared statements`)
          };
        }
      },
      {
        // Python f-strings or % formatting
        regex: /f["'](?:SELECT|INSERT|UPDATE|DELETE)\b.*?\{.+?\}/gi,
        generatePatch: (match, lang) => {
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
    patterns: [
      {
        // JS exec with concatenation or template literals
        regex: /\bexec\s*\(\s*(?:`[^`]*\$\{.+?\}[^`]*`|["'][^"']*(?:["']\s*\+\s*[\w.]+|[\w.]+\s*\+\s*["'])[^"']*)\s*(?:,|\))/gi,
        generatePatch: (match, lang) => {
          const before = match;
          const after = "execFile('ping', [host], (err, stdout, stderr) => {";
          return {
            before,
            after,
            diff: makeDiff(before, after)
          };
        }
      },
      {
        // Python subprocess/system with shell=True and dynamic variables
        regex: /\b(?:os\.system|subprocess\.run|subprocess\.Popen)\s*\(\s*(?:f["'][^"']*(?:\{.+?\})[^"']*["']|["'][^"']*(?:["']\s*\+\s*[\w.]+|[\w.]+\s*\+\s*["'])|[^,]+?\+[^,]+?)\s*(?:,\s*shell\s*=\s*True)?\s*\)/gi,
        generatePatch: (match, lang) => {
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
    patterns: [
      {
        regex: /\beval\s*\([^)]+\)/gi,
        generatePatch: (match, lang) => {
          const before = match;
          const after = lang === "python" ? "json.loads(user_input)" : "JSON.parse(userInput)";
          return {
            before,
            after: `${after} // Safe alternative for JSON evaluation`,
            diff: makeDiff(before, `${after} // Safe JSON parse`)
          };
        }
      },
      {
        regex: /\bnew\s+Function\s*\([^)]+\)/gi,
        generatePatch: (match, lang) => {
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
    explanation: "Allowing all origins ('*') while enabling credentials allows malicious websites to perform cross-origin requests, access sensitive session cookies, and steal private data on behalf ofauthenticated users.",
    recommendation: "Do not use origin: '*' with credentials: true. Instead, specify a whitelist of trusted domain origins or validate the request origin dynamically.",
    patterns: [
      {
        // origin: '*' along with credentials: true
        regex: /(?:origin\s*:\s*["']\*["'][\s\S]*?credentials\s*:\s*true|credentials\s*:\s*true[\s\S]*?origin\s*:\s*["']\*["'])/gi,
        generatePatch: (match, lang) => {
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
    patterns: [
      {
        // JS/TS readFile or createReadStream with req input
        regex: /\b(?:readFile|readFileSync|createReadStream)\s*\(\s*[^)]*?(?:req\.(?:query|body|params)|params\.\w+)[^)]*?\)/gi,
        generatePatch: (match, lang) => {
          const before = match;
          const after = "const safeName = path.basename(req.query.file);\nfs.readFileSync(path.join(SAFE_DIR, safeName))";
          return {
            before,
            after,
            diff: makeDiff(before, after)
          };
        }
      },
      {
        // Python open with request input
        regex: /\bopen\s*\(\s*[^)]*?(?:request\.(?:args|form|GET|POST|FILES|json|match_info)|params\.\w+)[^)]*?\)/gi,
        generatePatch: (match, lang) => {
          const before = match;
          const after = "safe_name = os.path.basename(request.args.get('filename'))\nwith open(os.path.join(SAFE_DIR, safe_name))";
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
    id: "weak-token-generation",
    title: "Cryptographically Weak Token Generation",
    severity: "medium",
    category: "Cryptography",
    explanation: "Math.random() (JavaScript) and the standard 'random' module (Python) generate pseudo-random numbers that are predictable. Using them for passwords, reset tokens, or session IDs allows attackers to guess credentials.",
    recommendation: "Use cryptographically secure random number generators (CSRNG) such as crypto.randomBytes() in Node.js or the 'secrets' module in Python.",
    patterns: [
      {
        // JS Math.random used near keywords or in variable assignment
        regex: /\b(?:token|session|password|reset|secret|key)\b[\w\s]*=[\w\s.]*?Math\.random\s*\(\s*\)/gi,
        generatePatch: (match, lang) => {
          const before = match;
          const after = match.replace(/Math\.random\s*\(\s*\)\.toString\(\d*\)\.substring\(\d*\)/i, "crypto.randomBytes(32).toString('hex')")
                             .replace(/Math\.random\s*\(\s*\)/i, "crypto.randomInt(100000, 999999)");
          return {
            before,
            after: `// Import crypto first\n${after}`,
            diff: makeDiff(before, after)
          };
        }
      },
      {
        // Python random used near keywords or in variable assignment
        regex: /\b(?:token|session|password|reset|secret|key)\b[\w\s]*=[\w\s.]*?random\.(?:random|randint|choice)\b/gi,
        generatePatch: (match, lang) => {
          const before = match;
          const after = match.replace(/random\.(?:random|randint|choice)/i, "secrets.token_hex(16)");
          return {
            before,
            after: `# Import secrets first\n${after}`,
            diff: makeDiff(before, after)
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
    patterns: [
      {
        // JS console.log containing sensitive fields
        regex: /\bconsole\.(?:log|info|warn|error)\s*\(\s*[^)]*?\b(?:password|token|secret|api_key|apikey|authorization|auth)\b[^)]*?\)/gi,
        generatePatch: (match, lang) => {
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
        generatePatch: (match, lang) => {
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
