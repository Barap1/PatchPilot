export interface RuleDoc {
  whatItDetects: string;
  whyItMatters: string;
  commonFalsePositives: string;
  saferPatterns: string;
}

export const ruleDocs: Record<string, RuleDoc> = {
  "hardcoded-secrets": {
    whatItDetects: "Unencrypted authentication credentials, private keys, API keys, or security tokens embedded directly in script code.",
    whyItMatters: "Exposing credentials in source code repositories allows anyone with codebase read access (including attackers scanning public repos or compromise hosts) to impersonate your system, access production systems, and steal data.",
    commonFalsePositives: "Dummy/placeholder values or testing credentials (e.g. 'sk-proj-1234567890abcdef12345678') in local test files.",
    saferPatterns: "Load credentials dynamically at runtime using environment variables (e.g., process.env in Node.js, os.environ in Python) or a dedicated secret vault (e.g. AWS Secrets Manager, HashiCorp Vault)."
  },
  "sql-injection": {
    whatItDetects: "Dynamic queries constructed by direct string interpolation, f-strings, or concatenation of variables into query lines.",
    whyItMatters: "Allows attackers to supply malicious database controls inside input variables, bypassing query constraints to read, drop, or alter database contents.",
    commonFalsePositives: "Concatenating internal system-defined constant parameters or numeric IDs that are validated and not supplied by user input.",
    saferPatterns: "Utilize parameterized statements/queries, prepared statements, or ORM/ODM drivers where variables are bound separate from query logic."
  },
  "command-injection": {
    whatItDetects: "Direct system shell command triggers (exec, os.system) executed with variable string concatenation.",
    whyItMatters: "Attackers can input shell control metacharacters (like ;, &, |) to trigger arbitrary background host OS commands, taking full control of the web server.",
    commonFalsePositives: "Shell operations using hardcoded constants or internally validated parameter configurations.",
    saferPatterns: "Avoid triggering raw shell executions. Use process execution functions that run executable binaries directly with an arguments array (e.g. execFile or spawn with shell: false)."
  },
  "unsafe-eval": {
    whatItDetects: "Usage of eval() or dynamic Function compilation constructors that compile arbitrary strings into operational code.",
    whyItMatters: "Allows remote code execution (RCE) if user inputs influence the executed string, bypassing application runtime constraints.",
    commonFalsePositives: "Local testing scripts, browser extensions, or sandboxed execution runtimes.",
    saferPatterns: "Use structured parsers (e.g. JSON.parse()) or lookup tables mapping input keywords to predefined callback functions."
  },
  "insecure-cors": {
    whatItDetects: "Cross-Origin Resource Sharing (CORS) header configs enabling credential sharing while mapping to origin wildcard (*).",
    whyItMatters: "Allows any domain on the internet to send cross-origin requests, capture session identification cookies, and read sensitive data on behalf of authenticated clients.",
    commonFalsePositives: "Public APIs hosting public data (e.g., public weather or map tiles) where cookie authentication is not used.",
    saferPatterns: "Whitelist authorized origins specifically, or check incoming request origins dynamically and respond only with valid trusted domains."
  },
  "path-traversal": {
    whatItDetects: "Opening files, reading streams, or writing contents using directory paths built from dynamic string parameters.",
    whyItMatters: "Allows attackers to request sensitive server host files (like /etc/passwd, configuration scripts, or credentials) by inputting relative path keys (e.g. '../../etc/passwd').",
    commonFalsePositives: "Hardcoded absolute/relative path reads or validated file names mapping to specific assets.",
    saferPatterns: "Extract the base filename using path.basename(), and build path coordinates utilizing path.join() against a verified, strict base directory."
  },
  "weak-token-generation": {
    whatItDetects: "Pseudo-random generators (Math.random() in Node, random module in Python) utilized to output variables mapped to keys or tokens.",
    whyItMatters: "Pseudo-random values are mathematically predictable. An attacker who captures a few tokens can predict future or past session tokens, reset keys, or passwords.",
    commonFalsePositives: "General non-security functions like game logic, pagination, animations, or styling layouts.",
    saferPatterns: "Use cryptographically secure random number generators (CSRNG) such as Node's crypto.randomBytes() or Python's secrets module."
  },
  "sensitive-logging": {
    whatItDetects: "Debug lines (console.log, print, logging) logging variables named after passwords, tokens, API keys, or authorization credentials.",
    whyItMatters: "Logs are stored in plaintext on disk, indexed by log aggregation tools, and shared with administrators/third-parties, exposing passwords to unauthorized access.",
    commonFalsePositives: "Logging variables that contain non-sensitive parameters or masked variables.",
    saferPatterns: "Mask or redact credentials before logging them, or use a custom logging framework that automatically strips sensitive key-value pairs."
  }
};
