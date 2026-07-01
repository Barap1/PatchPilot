/**
 * Redacts secrets, credentials, and sensitive values from text.
 * Replaces them with a redacted placeholder to ensure no raw secrets are leaked.
 */
export function redactSecrets(text: string): string {
  if (!text) return text;
  let redacted = text;

  // 1. OpenAI-style sk- keys: sk-proj- followed by alphanumeric/hyphens
  redacted = redacted.replace(/\bsk-[a-zA-Z0-9-]{20,}\b/g, (match) => {
    if (match.length <= 16) return "[REDACTED]";
    return match.substring(0, 11) + "...REDACTED..." + match.substring(match.length - 5);
  });

  // 2. AWS Access Key IDs: AKIA followed by 16 uppercase alphanumeric
  redacted = redacted.replace(/\bAKIA[A-Z0-9]{16}\b/g, (match) => {
    return match.substring(0, 4) + "...REDACTED..." + match.substring(match.length - 4);
  });

  // 3. Private key blocks (PEM files)
  redacted = redacted.replace(/-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----/gi, (match) => {
    const lines = match.split("\n");
    if (lines.length > 2) {
      return `${lines[0]}\n...REDACTED...\n${lines[lines.length - 1]}`;
    }
    return "-----BEGIN PRIVATE KEY-----\n...REDACTED...\n-----END PRIVATE KEY-----";
  });

  // 4. JWT-like tokens (three dot-separated base64-like components)
  redacted = redacted.replace(/\beyJhbGciOi[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\b/g, (match) => {
    return match.substring(0, 12) + "...REDACTED..." + match.substring(match.length - 8);
  });

  // 5. Assignment to password/token/secret/api_key/private_key
  // Matches key: "val" or key = "val"
  redacted = redacted.replace(/(\b(?:password|token|secret|api_key|apikey|private_key)\b(?:\s*:\s*[\w<>|[\]]+)?\s*[:=]\s*)(["'])([^"'\r\n]{6,})\2/gi, (match, prefix, quote, val) => {
    if (val.includes("...REDACTED...") || val === "[REDACTED]") {
      return match;
    }
    let redactedVal;
    if (val.startsWith("sk-") || val.startsWith("AKIA")) {
      // These are already handled by rule 1 & 2 if matched as full tokens, but in case they are nested:
      redactedVal = val.length > 10 
        ? val.substring(0, 6) + "...REDACTED..." + val.substring(val.length - 4)
        : "...REDACTED...";
    } else {
      redactedVal = val.length > 8
        ? val.substring(0, 3) + "...REDACTED..." + val.substring(val.length - 3)
        : "...REDACTED...";
    }
    return `${prefix}${quote}${redactedVal}${quote}`;
  });

  // 6. Authorization headers (Bearer, Basic)
  redacted = redacted.replace(/\b(Authorization\s*[:=]\s*["']?)(?:Bearer|Basic)\s+([a-zA-Z0-9-._~+/]+=*)(["']?)/gi, (match, prefix, token, suffix) => {
    if (token.includes("...REDACTED...")) return match;
    const redactedToken = token.length > 8 
      ? token.substring(0, 4) + "...REDACTED..." + token.substring(token.length - 4)
      : "...REDACTED...";
    const isBearer = match.toLowerCase().includes("bearer");
    return `${prefix}${isBearer ? "Bearer" : "Basic"} ${redactedToken}${suffix}`;
  });

  // 7. Obvious credentials in connection strings/URLs: proto://user:password@host
  redacted = redacted.replace(/(\b[a-zA-Z0-9+-.]+:\/\/)([^:\s]+):([^@\s]+)(@[a-zA-Z0-9_.-]+)/gi, (match, proto, user, pass, host) => {
    if (pass.includes("...REDACTED...")) return match;
    return `${proto}${user}:...REDACTED...${host}`;
  });

  // 8. Long high-entropy tokens: alphanumeric/hex strings of length >= 32
  redacted = redacted.replace(/\b([a-zA-Z0-9]{32,})\b/g, (match) => {
    if (match.includes("REDACTED") || match.includes("redacted")) return match;
    // Don't redact common long words or strings of purely alphabetical characters unless very long (>=40)
    if (/^[a-zA-Z]+$/.test(match) && match.length < 40) return match;
    // Don't redact if it is a common HTML tag, JSON key or import/export code structure
    if (["constructor", "supports_credentials"].includes(match)) return match;
    return match.substring(0, 6) + "...REDACTED..." + match.substring(match.length - 4);
  });

  return redacted;
}
