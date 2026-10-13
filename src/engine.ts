import { createHash } from "node:crypto";
import { calculateShannonEntropy, isLikelyFalsePositive } from "./entropy.js";
import { BUILTIN_PATTERNS } from "./patterns.js";
import type { DetectedSecret, ScanOptions, ScanResult, SecretPattern } from "./types.js";

export class AgentShieldEngine {
  private patterns: SecretPattern[];
  private vaultMap: Map<string, string> = new Map();
  private reverseVaultMap: Map<string, string> = new Map();

  constructor(customPatterns?: SecretPattern[]) {
    this.patterns = [...BUILTIN_PATTERNS, ...(customPatterns || [])];
  }

  /**
   * Scans text content, detects known and unknown high-entropy secrets, and redacts them safely.
   */
  public scanAndRedact(text: string, options: ScanOptions = {}): ScanResult {
    const findings: DetectedSecret[] = [];
    const allowlist = new Set(options.allowlist || []);
    const entropyThreshold = options.entropyThreshold ?? 4.5;
    const detectedSecretsSet = new Set<string>();
    let sanitizedText = text;

    const activePatterns = [
      ...this.patterns,
      ...(options.customPatterns || []),
    ];

    // 1. Pattern-based detection
    for (const pattern of activePatterns) {
      // Ensure global flag 'g' is present to prevent zero-length match infinite loops
      const flags = pattern.regex.flags.includes("g") ? pattern.regex.flags : `${pattern.regex.flags}g`;
      const regex = new RegExp(pattern.regex.source, flags);
      let match = regex.exec(text);

      while (match !== null) {
        // Guard against infinite loops with zero-length matching regex patterns
        if (match[0].length === 0) {
          regex.lastIndex++;
          match = regex.exec(text);
          continue;
        }

        // match[1] if capture group exists, else match[0]
        const rawSecret = match[1] || match[0];

        if (allowlist.has(rawSecret) || isLikelyFalsePositive(rawSecret)) {
          match = regex.exec(text);
          continue;
        }

        detectedSecretsSet.add(rawSecret);

        // Calculate line and column
        const preMatch = text.substring(0, match.index);
        const line = preMatch.split("\n").length;
        const lastNewline = preMatch.lastIndexOf("\n");
        const column = lastNewline === -1 ? match.index + 1 : match.index - lastNewline;

        const entropy = calculateShannonEntropy(rawSecret);

        // Generate deterministic 16-hex collision-resistant token
        const placeholder = this.getOrCreateRedactedToken(rawSecret, pattern.id, options.maskStyle);

        findings.push({
          patternId: pattern.id,
          patternName: pattern.name,
          category: pattern.category,
          severity: pattern.severity,
          raw: rawSecret,
          redacted: placeholder,
          line,
          column,
          entropy,
        });

        match = regex.exec(text);
      }
    }

    // 2. Active High-Entropy Discovery for unknown credentials / passwords
    // Tokenizes assignments, quotes, and standalone candidate alphanumeric strings
    const tokenRegex = /(?:["'`=:\s])([a-zA-Z0-9+/=_\-]{20,128})(?:["'`\s;\n]|$)/g;
    let tokenMatch = tokenRegex.exec(text);

    while (tokenMatch !== null) {
      if (tokenMatch[0].length === 0) {
        tokenRegex.lastIndex++;
        tokenMatch = tokenRegex.exec(text);
        continue;
      }

      const candidate = tokenMatch[1];
      if (
        !detectedSecretsSet.has(candidate) &&
        !allowlist.has(candidate) &&
        !isLikelyFalsePositive(candidate)
      ) {
        const entropy = calculateShannonEntropy(candidate);
        // Shannon entropy threshold (standard 4.5+ bits/char indicates high randomness)
        if (entropy >= entropyThreshold) {
          detectedSecretsSet.add(candidate);

          const preMatch = text.substring(0, tokenMatch.index);
          const line = preMatch.split("\n").length;
          const lastNewline = preMatch.lastIndexOf("\n");
          const column = lastNewline === -1 ? tokenMatch.index + 1 : tokenMatch.index - lastNewline;

          const placeholder = this.getOrCreateRedactedToken(
            candidate,
            "high-entropy-secret",
            options.maskStyle,
          );

          findings.push({
            patternId: "high-entropy-secret",
            patternName: "Generic High-Entropy Secret",
            category: "generic",
            severity: "high",
            raw: candidate,
            redacted: placeholder,
            line,
            column,
            entropy,
          });
        }
      }

      tokenMatch = tokenRegex.exec(text);
    }

    // 3. Perform safe deterministic redactions
    // Sort descending by raw secret length to prevent shorter substrings colliding with longer tokens
    const uniqueRedactions = Array.from(
      new Map(findings.map((f) => [f.raw, f.redacted])).entries(),
    ).sort((a, b) => b[0].length - a[0].length);

    for (const [raw, redacted] of uniqueRedactions) {
      sanitizedText = sanitizedText.split(raw).join(redacted);
    }

    // 4. Default raw masking in findings unless explicitly opted in
    const safeFindings = findings.map((f) => ({
      ...f,
      raw: options.includeRaw ? f.raw : f.redacted,
    }));

    return {
      hasSecrets: findings.length > 0,
      totalFound: findings.length,
      findings: safeFindings,
      sanitizedText,
      vaultMap: options.includeRaw ? new Map(this.vaultMap) : new Map(),
    };
  }

  /**
   * Rehydrates a redacted text string back to its original secrets using the in-memory vault.
   */
  public rehydrate(redactedText: string): string {
    let rehydrated = redactedText;
    for (const [placeholder, original] of this.vaultMap.entries()) {
      rehydrated = rehydrated.split(placeholder).join(original);
    }
    return rehydrated;
  }

  /**
   * Generates deterministic, collision-resistant redaction tokens using SHA-256 (16 hex chars).
   */
  private getOrCreateRedactedToken(
    raw: string,
    patternId: string,
    maskStyle: "token" | "hash" | "asterisk" = "token",
  ): string {
    const existing = this.reverseVaultMap.get(raw);
    if (existing) {
      return existing;
    }

    let token = "";
    if (maskStyle === "asterisk") {
      token = raw.substring(0, 4) + "*".repeat(Math.max(6, raw.length - 8)) + raw.slice(-4);
    } else {
      // 16 hex characters of SHA-256 ensures zero collision across keys
      const hexHash = createHash("sha256").update(raw).digest("hex").substring(0, 16);
      const cleanId = patternId.toUpperCase().replace(/[^A-Z0-9]/g, "_");
      token = `[AGENT_SHIELD:${cleanId}:${hexHash}]`;
    }

    this.vaultMap.set(token, raw);
    this.reverseVaultMap.set(raw, token);
    return token;
  }
}
