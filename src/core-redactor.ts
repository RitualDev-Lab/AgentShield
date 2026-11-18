import { createHash } from "node:crypto";

export interface CoreSecretRule {
  id: string;
  name: string;
  category: "ai" | "cloud" | "vcs" | "payment" | "database" | "private-key" | "generic";
  severity: "critical" | "high" | "medium";
  /** Guaranteed linear-time DFA-safe pattern (no nested quantifiers or backreferences) */
  pattern: RegExp;
}

export interface CoreRedactionFinding {
  ruleId: string;
  ruleName: string;
  category: CoreSecretRule["category"];
  severity: CoreSecretRule["severity"];
  line: number;
  column: number;
  file?: string;
  redacted: string;
  entropy?: number;
}

export interface CoreRedactionOptions {
  /** Shannon entropy threshold for high-entropy assignment detection (default: 4.5) */
  entropyThreshold?: number;
  /** Maximum scan budget per text chunk in milliseconds (default: 25ms circuit-breaker) */
  maxScanMs?: number;
  /** Allowlisted literal substrings to ignore */
  allowlist?: string[];
  /** Custom extra linear-time rules */
  extraRules?: CoreSecretRule[];
}

export interface CoreRedactionResult {
  hasSecrets: boolean;
  totalFound: number;
  findings: CoreRedactionFinding[];
  sanitizedText: string;
  elapsedMs: number;
  circuitBreakerTripped: boolean;
}

export interface StagedDiffRedactionResult {
  passed: boolean;
  filesScanned: number;
  findings: CoreRedactionFinding[];
  sanitizedDiff: string;
  elapsedMs: number;
}

/**
 * Shared linear-time DFA-safe secret signature catalog designed for zero-dependency reuse
 * across AgentShield, PromptShield, DBShield, and mcp-builder-kit.
 * All patterns avoid catastrophic backtracking (ReDoS-free).
 */
export const CORE_SECRET_RULES: CoreSecretRule[] = [
  {
    id: "openai-api-key",
    name: "OpenAI API Key",
    category: "ai",
    severity: "critical",
    pattern: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,160}\b/g,
  },
  {
    id: "anthropic-api-key",
    name: "Anthropic API Key",
    category: "ai",
    severity: "critical",
    pattern: /\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{20,120}\b/g,
  },
  {
    id: "google-ai-key",
    name: "Google / Gemini API Key",
    category: "ai",
    severity: "critical",
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
  },
  {
    id: "aws-access-key-id",
    name: "AWS Access Key ID",
    category: "cloud",
    severity: "critical",
    pattern: /\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b/g,
  },
  {
    id: "github-pat",
    name: "GitHub Personal Access Token",
    category: "vcs",
    severity: "critical",
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,64}\b/g,
  },
  {
    id: "github-fine-grained-pat",
    name: "GitHub Fine-Grained PAT",
    category: "vcs",
    severity: "critical",
    pattern: /\bgithub_pat_[A-Za-z0-9_]{22,120}\b/g,
  },
  {
    id: "stripe-live-key",
    name: "Stripe Secret / Restricted Key",
    category: "payment",
    severity: "critical",
    pattern: /\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{20,99}\b/g,
  },
  {
    id: "slack-token",
    name: "Slack Bot / User Token",
    category: "generic",
    severity: "high",
    pattern: /\bxox[baprs]-[0-9A-Za-z-]{16,80}\b/g,
  },
  {
    id: "postgres-dsn",
    name: "Database Connection URI with Credentials",
    category: "database",
    severity: "critical",
    pattern:
      /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|rediss?):\/\/[^\s:@"'`]{1,64}:[^\s@"'`]{4,128}@[^\s"'`]{3,128}/g,
  },
  {
    id: "pem-private-key",
    name: "PEM Private Key Header",
    category: "private-key",
    severity: "critical",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g,
  },
  {
    id: "jwt-token",
    name: "JSON Web Token (JWT)",
    category: "generic",
    severity: "medium",
    pattern: /\beyJ[A-Za-z0-9_-]{10,120}\.eyJ[A-Za-z0-9_-]{10,200}\.[A-Za-z0-9_-]{16,120}\b/g,
  },
];

const HIGH_ENTROPY_ASSIGNMENT =
  /\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret|password|passwd|db[_-]?pass)\s*[:=]\s*["'`]([A-Za-z0-9/+_=.-]{20,128})["'`]/gi;

/**
 * Computes Shannon entropy H(X) in bits per character.
 */
export function calculateShannonEntropy(input: string): number {
  if (!input || input.length === 0) return 0;
  const freq = new Map<string, number>();
  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }
  let entropy = 0;
  const len = input.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(4));
}

function makeRedactionToken(ruleId: string, rawSecret: string): string {
  const shortHash = createHash("sha256").update(rawSecret).digest("hex").slice(0, 12);
  return `[AGENTSHIELD_REDACTED:${ruleId.toUpperCase()}:${shortHash}]`;
}

function computeLineCol(text: string, offset: number): { line: number; column: number } {
  let line = 1;
  let lastNewline = -1;
  for (let i = 0; i < offset; i++) {
    if (text.charCodeAt(i) === 10) {
      line++;
      lastNewline = i;
    }
  }
  return { line, column: offset - lastNewline };
}

/**
 * Zero-dependency shared core secret redactor with:
 * - Linear-time DFA-safe regex catalog
 * - Shannon entropy (H > 4.5) credential assignment detection
 * - Hard per-chunk latency circuit-breaker (default 25ms)
 * - Unified staged Git diff AST/line redaction
 */
export class CoreRedactor {
  private readonly rules: CoreSecretRule[];
  private readonly defaultThreshold: number;
  private readonly defaultMaxScanMs: number;
  private readonly defaultAllowlist: string[];

  constructor(options: CoreRedactionOptions = {}) {
    this.rules = [...CORE_SECRET_RULES, ...(options.extraRules || [])];
    this.defaultThreshold = options.entropyThreshold ?? 4.5;
    this.defaultMaxScanMs = options.maxScanMs ?? 25;
    this.defaultAllowlist = options.allowlist || [];
  }

  public scanAndRedact(
    input: string,
    overrideOptions: CoreRedactionOptions = {},
  ): CoreRedactionResult {
    const startedAt = performance.now();
    const maxScanMs = overrideOptions.maxScanMs ?? this.defaultMaxScanMs;
    const entropyThreshold = overrideOptions.entropyThreshold ?? this.defaultThreshold;
    const allowlist = overrideOptions.allowlist ?? this.defaultAllowlist;

    if (!input) {
      return {
        hasSecrets: false,
        totalFound: 0,
        findings: [],
        sanitizedText: "",
        elapsedMs: 0,
        circuitBreakerTripped: false,
      };
    }

    const matches: Array<{
      start: number;
      end: number;
      raw: string;
      ruleId: string;
      ruleName: string;
      category: CoreSecretRule["category"];
      severity: CoreSecretRule["severity"];
      entropy?: number;
    }> = [];

    let circuitBreakerTripped = false;

    for (const rule of this.rules) {
      if (performance.now() - startedAt > maxScanMs) {
        circuitBreakerTripped = true;
        break;
      }

      const rx = new RegExp(rule.pattern.source, rule.pattern.flags);
      let m = rx.exec(input);
      while (m !== null) {
        if (performance.now() - startedAt > maxScanMs) {
          circuitBreakerTripped = true;
          break;
        }
        const raw = m[0];
        if (!allowlist.some((allowed) => allowed && raw.includes(allowed))) {
          matches.push({
            start: m.index,
            end: m.index + raw.length,
            raw,
            ruleId: rule.id,
            ruleName: rule.name,
            category: rule.category,
            severity: rule.severity,
            entropy: calculateShannonEntropy(raw),
          });
        }
        if (rx.lastIndex === m.index) rx.lastIndex++;
        m = rx.exec(input);
      }

      if (circuitBreakerTripped) break;
    }

    // Entropy-based assignment check if still within latency budget
    if (!circuitBreakerTripped && performance.now() - startedAt <= maxScanMs) {
      const entropyRx = new RegExp(HIGH_ENTROPY_ASSIGNMENT.source, HIGH_ENTROPY_ASSIGNMENT.flags);
      let m = entropyRx.exec(input);
      while (m !== null) {
        if (performance.now() - startedAt > maxScanMs) {
          circuitBreakerTripped = true;
          break;
        }
        const candidate = m[1];
        if (candidate && !allowlist.some((allowed) => allowed && candidate.includes(allowed))) {
          const h = calculateShannonEntropy(candidate);
          if (h > entropyThreshold) {
            const valOffset = m[0].indexOf(candidate);
            const start = m.index + (valOffset >= 0 ? valOffset : 0);
            const end = start + candidate.length;
            const overlaps = matches.some(
              (existing) => !(end <= existing.start || start >= existing.end),
            );
            if (!overlaps) {
              matches.push({
                start,
                end,
                raw: candidate,
                ruleId: "high-entropy-secret",
                ruleName: "High-Entropy Credential Assignment",
                category: "generic",
                severity: "high",
                entropy: h,
              });
            }
          }
        }
        if (entropyRx.lastIndex === m.index) entropyRx.lastIndex++;
        m = entropyRx.exec(input);
      }
    }

    // Sort and deduplicate overlapping spans
    matches.sort((a, b) => a.start - b.start || b.end - a.end);
    const nonOverlapping: typeof matches = [];
    let cursor = -1;
    for (const match of matches) {
      if (match.start >= cursor) {
        nonOverlapping.push(match);
        cursor = match.end;
      }
    }

    let sanitized = "";
    let lastPos = 0;
    const findings: CoreRedactionFinding[] = [];

    for (const match of nonOverlapping) {
      const token = makeRedactionToken(match.ruleId, match.raw);
      sanitized += input.slice(lastPos, match.start) + token;
      lastPos = match.end;
      const { line, column } = computeLineCol(input, match.start);
      findings.push({
        ruleId: match.ruleId,
        ruleName: match.ruleName,
        category: match.category,
        severity: match.severity,
        line,
        column,
        redacted: token,
        entropy: match.entropy,
      });
    }
    sanitized += input.slice(lastPos);

    const elapsedMs = Number((performance.now() - startedAt).toFixed(3));
    return {
      hasSecrets: findings.length > 0,
      totalFound: findings.length,
      findings,
      sanitizedText: sanitized,
      elapsedMs,
      circuitBreakerTripped,
    };
  }

  /**
   * Scans and redacts added lines (`+`) in a unified Git staged diff, annotating findings
   * with exact repository file path and target line numbers.
   */
  public redactStagedDiff(
    unifiedDiff: string,
    overrideOptions: CoreRedactionOptions = {},
  ): StagedDiffRedactionResult {
    const startedAt = performance.now();
    const lines = unifiedDiff.split("\n");
    const findings: CoreRedactionFinding[] = [];
    const outputLines: string[] = [];
    const filesSeen = new Set<string>();

    let currentFile = "unknown";
    let currentLineNum = 0;

    for (const rawLine of lines) {
      if (rawLine.startsWith("+++ b/")) {
        currentFile = rawLine.slice(6).trim();
        filesSeen.add(currentFile);
        outputLines.push(rawLine);
        continue;
      }
      if (rawLine.startsWith("@@ ")) {
        const hunkMatch = rawLine.match(/\+(\d+)/);
        currentLineNum = hunkMatch ? Number.parseInt(hunkMatch[1], 10) - 1 : 0;
        outputLines.push(rawLine);
        continue;
      }
      if (rawLine.startsWith("+") && !rawLine.startsWith("+++")) {
        currentLineNum++;
        const content = rawLine.slice(1);
        const res = this.scanAndRedact(content, overrideOptions);
        if (res.hasSecrets) {
          for (const f of res.findings) {
            findings.push({
              ...f,
              file: currentFile,
              line: currentLineNum,
            });
          }
          outputLines.push(`+${res.sanitizedText}`);
        } else {
          outputLines.push(rawLine);
        }
        continue;
      }
      if (!rawLine.startsWith("-") && !rawLine.startsWith("\\")) {
        currentLineNum++;
      }
      outputLines.push(rawLine);
    }

    return {
      passed: findings.length === 0,
      filesScanned: filesSeen.size,
      findings,
      sanitizedDiff: outputLines.join("\n"),
      elapsedMs: Number((performance.now() - startedAt).toFixed(3)),
    };
  }
}

const defaultRedactor = new CoreRedactor();

export function scanText(input: string, options?: CoreRedactionOptions): CoreRedactionFinding[] {
  return defaultRedactor.scanAndRedact(input, options).findings;
}

export function redactText(input: string, options?: CoreRedactionOptions): CoreRedactionResult {
  return defaultRedactor.scanAndRedact(input, options);
}

export function redactStagedDiff(
  unifiedDiff: string,
  options?: CoreRedactionOptions,
): StagedDiffRedactionResult {
  return defaultRedactor.redactStagedDiff(unifiedDiff, options);
}
