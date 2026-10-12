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
   * Scans text content, detects secrets, and redacts them safely.
   */
  public scanAndRedact(text: string, options: ScanOptions = {}): ScanResult {
    const findings: DetectedSecret[] = [];
    const allowlist = new Set(options.allowlist || []);
    let sanitizedText = text;

    const lines = text.split("\n");

    // 1. Pattern-based detection
    for (const pattern of this.patterns) {
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      let match = regex.exec(text);
      while (match !== null) {
        // match[1] if group exists, else match[0]
        const rawSecret = match[1] || match[0];

        if (allowlist.has(rawSecret) || isLikelyFalsePositive(rawSecret)) {
          continue;
        }

        // Calculate line and column
        const preMatch = text.substring(0, match.index);
        const line = preMatch.split("\n").length;
        const lastNewline = preMatch.lastIndexOf("\n");
        const column = lastNewline === -1 ? match.index + 1 : match.index - lastNewline;

        const entropy = calculateShannonEntropy(rawSecret);

        // Generate deterministic token
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

    // 2. Perform safe redactions
    for (const finding of findings) {
      sanitizedText = sanitizedText.split(finding.raw).join(finding.redacted);
    }

    return {
      hasSecrets: findings.length > 0,
      totalFound: findings.length,
      findings,
      sanitizedText,
      vaultMap: new Map(this.vaultMap),
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
      const shortHash = Buffer.from(raw).toString("base64url").substring(0, 6);
      const cleanId = patternId.toUpperCase().replace(/[^A-Z0-9]/g, "_");
      token = `[AGENT_SHIELD:${cleanId}:${shortHash}]`;
    }

    this.vaultMap.set(token, raw);
    this.reverseVaultMap.set(raw, token);
    return token;
  }
}
