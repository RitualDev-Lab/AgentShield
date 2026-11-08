import { randomUUID } from "node:crypto";
import { isHighEntropySecret, isLikelyFalsePositive } from "./entropy.js";
import { BUILTIN_PATTERNS } from "./patterns.js";

export interface SurrogateTokenMapping {
  surrogate: string;
  original: string;
  category: string;
  entropy: number;
  createdAt: number;
}

export interface SurrogateRedactionResult {
  sanitized: string;
  surrogatesCount: number;
  mappings: SurrogateTokenMapping[];
}

/**
 * Common high-risk credential regular expressions for deterministic AST token matching.
 */
const DETERMINISTIC_CREDENTIAL_PATTERNS: Array<{
  name: string;
  regex: RegExp;
}> = [
  { name: "aws_access_key", regex: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: "github_pat", regex: /\bghp_[a-zA-Z0-9]{36}\b/ },
  { name: "github_fine_grained", regex: /\bgithub_pat_[a-zA-Z0-9_]{82}\b/ },
  { name: "openai_api_key", regex: /\bsk-[a-zA-Z0-9]{48}\b/ },
  { name: "anthropic_api_key", regex: /\bsk-ant-[a-zA-Z0-9_\-]{80,}\b/ },
  { name: "bearer_token", regex: /\bBearer\s+([a-zA-Z0-9_\-\.]{24,})\b/i },
  {
    name: "generic_api_key_flag",
    regex: /(?:--api[-_]?key|--token|--secret)[=\s]+(["']?)([a-zA-Z0-9_\-\.]{16,})\1/i,
  },
];

/**
 * In-Memory Volatile Surrogate Token Manager.
 * Replaces high-risk secrets and high-entropy tokens with in-memory volatile decoy surrogates
 * (`RD_SURROGATE_<UUID>`) before child process invocation, ensuring that execution environments,
 * memory dumps, error logs, and subshell wrappers never see or leak plaintext secrets.
 */
export class SurrogateManager {
  private readonly forwardMap = new Map<string, SurrogateTokenMapping>(); // surrogate -> mapping
  private readonly reverseMap = new Map<string, string>(); // original -> surrogate
  private readonly prefix: string;

  constructor(prefix = "RD_SURROGATE") {
    this.prefix = prefix;
  }

  /**
   * Generates or retrieves an existing volatile decoy surrogate token for a given secret.
   */
  public getOrCreateSurrogate(original: string, category = "generic_secret", entropy = 0): string {
    const existing = this.reverseMap.get(original);
    if (existing) {
      return existing;
    }

    const surrogate = `${this.prefix}_${randomUUID().replace(/-/g, "").toUpperCase()}`;
    const mapping: SurrogateTokenMapping = {
      surrogate,
      original,
      category,
      entropy,
      createdAt: Date.now(),
    };

    this.forwardMap.set(surrogate, mapping);
    this.reverseMap.set(original, surrogate);
    return surrogate;
  }

  /**
   * Restores all surrogate tokens in a given string back to their original values.
   */
  public restoreSurrogates(text: string): string {
    if (!text || this.forwardMap.size === 0) return text;

    let restored = text;
    for (const [surrogate, mapping] of this.forwardMap.entries()) {
      restored = restored.replaceAll(surrogate, mapping.original);
    }
    return restored;
  }

  /**
   * Replaces all surrogate tokens with standard static redaction placeholders for public audit logging.
   */
  public maskSurrogates(text: string, placeholder = "[REDACTED_SECRET]"): string {
    if (!text || this.forwardMap.size === 0) return text;

    let masked = text;
    for (const surrogate of this.forwardMap.keys()) {
      masked = masked.replaceAll(surrogate, placeholder);
    }
    return masked;
  }

  /**
   * Retrieves all active in-memory mappings.
   */
  public getMappings(): SurrogateTokenMapping[] {
    return Array.from(this.forwardMap.values());
  }

  /**
   * Returns whether a given string is a recognized volatile surrogate token.
   */
  public isSurrogate(token: string): boolean {
    return this.forwardMap.has(token);
  }

  /**
   * Volatile memory purge: destroys all surrogate mappings immediately.
   */
  public clear(): void {
    this.forwardMap.clear();
    this.reverseMap.clear();
  }

  /**
   * Inspects a string, identifies credentials via deterministic patterns and entropy analysis,
   * and substitutes them with volatile decoy surrogates.
   */
  public redactWithSurrogates(content: string): SurrogateRedactionResult {
    if (!content) {
      return { sanitized: "", surrogatesCount: 0, mappings: [] };
    }

    let sanitized = content;
    const detectedMappings: SurrogateTokenMapping[] = [];

    // 1. Check deterministic credential patterns
    for (const pattern of DETERMINISTIC_CREDENTIAL_PATTERNS) {
      sanitized = sanitized.replace(pattern.regex, (match, ...args) => {
        // If first capture group is a string, use it; otherwise use the full match
        const captured = typeof args[0] === "string" ? args[0] : match;
        const target = captured || match;
        if (typeof target !== "string" || isLikelyFalsePositive(target)) return match;
        const surrogate = this.getOrCreateSurrogate(target, pattern.name, 5.0);
        const mapping = this.forwardMap.get(surrogate);
        if (mapping) detectedMappings.push(mapping);
        return match.replace(target, surrogate);
      });
    }

    // 2. Check engine rule catalog patterns
    for (const p of BUILTIN_PATTERNS) {
      sanitized = sanitized.replace(p.pattern, (match) => {
        if (isLikelyFalsePositive(match)) return match;
        const surrogate = this.getOrCreateSurrogate(match, p.name, 4.8);
        const mapping = this.forwardMap.get(surrogate);
        if (mapping) detectedMappings.push(mapping);
        return surrogate;
      });
    }

    // 3. Check standalone tokens for high Shannon entropy (H > 4.5)
    const tokenRegex = /[^\s"':=;,|&><]+/g;
    let tokenMatch: RegExpExecArray | null = tokenRegex.exec(content);
    while (tokenMatch !== null) {
      const candidate = tokenMatch[0];
      if (
        candidate.length >= 16 &&
        !candidate.startsWith(this.prefix) &&
        !isLikelyFalsePositive(candidate)
      ) {
        const { isSecret, entropy } = isHighEntropySecret(candidate, 4.5);
        if (isSecret && !this.reverseMap.has(candidate)) {
          const surrogate = this.getOrCreateSurrogate(candidate, "high_entropy_secret", entropy);
          sanitized = sanitized.replaceAll(candidate, surrogate);
          const mapping = this.forwardMap.get(surrogate);
          if (mapping) detectedMappings.push(mapping);
        }
      }
      tokenMatch = tokenRegex.exec(content);
    }

    return {
      sanitized,
      surrogatesCount: this.forwardMap.size,
      mappings: Array.from(new Set(detectedMappings)),
    };
  }
}
