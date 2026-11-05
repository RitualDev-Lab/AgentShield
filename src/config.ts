import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { SecretPattern } from "./types.js";

export interface AntigravityProfileConfig {
  enabled?: boolean;
  profile?: string;
  interceptTools?: string[];
  enforceSandbox?: boolean;
  requireIsolation?: boolean;
  quarantineOnCanaryTrip?: boolean;
  protectedPatterns?: string[];
  hooks?: {
    preCommand?: string;
    preWrite?: string;
    auditLog?: string;
  };
}

export interface AgentShieldConfig {
  version?: string;
  allowlist?: string[];
  entropyThreshold?: number;
  maskStyle?: "token" | "hash" | "asterisk";
  customPatterns?: Array<{
    id: string;
    name: string;
    category?: "cloud" | "ai" | "saas" | "vcs" | "crypto" | "generic";
    severity?: "critical" | "high" | "medium";
    regex: string;
    description?: string;
  }>;
  ci?: {
    failOnSeverity?: "critical" | "high" | "medium";
    ignoreFiles?: string[];
  };
  enterprise?: {
    apiKey?: string;
    endpoint?: string;
    vault?: {
      provider?: "hashicorp" | "aws_secrets_manager" | "azure_key_vault" | "mock";
      address?: string;
      roleId?: string;
      path?: string;
    };
    siem?: {
      enabled?: boolean;
      format?: "cef" | "json" | "syslog";
      webhookUrl?: string;
    };
    compliance?: {
      frameworks?: Array<"soc2" | "pci_dss" | "hipaa" | "iso27001">;
      strictMode?: boolean;
    };
  };
  antigravity?: AntigravityProfileConfig;
}

export function loadConfig(rootDir: string = process.cwd()): AgentShieldConfig | null {
  const configFiles = [
    join(rootDir, ".agentshield.json"),
    join(rootDir, "agentshield.config.json"),
  ];

  for (const file of configFiles) {
    if (existsSync(file)) {
      try {
        const raw = readFileSync(file, "utf8");
        return JSON.parse(raw);
      } catch (err) {
        console.warn(`⚠️ Warning: Failed to parse configuration file at '${file}':`, err);
      }
    }
  }

  return null;
}

/**
 * Static analyzer for Catastrophic Backtracking (ReDoS) vulnerability detection.
 * Validates custom regex patterns against polynomial and exponential backtracking constructs
 * (nested quantifiers like (a+)+ or disjunctions with nested repetition like (a+|b)+).
 */
export function validateReDoSSafety(pattern: string): { safe: boolean; reason?: string } {
  if (!pattern || typeof pattern !== "string") {
    return { safe: false, reason: "Pattern must be a non-empty string" };
  }

  // 1. Guard against oversized regex patterns
  if (pattern.length > 500) {
    return { safe: false, reason: "Pattern exceeds maximum allowed length of 500 characters" };
  }

  // 2. Detect nested quantifiers (e.g. (a+)+, (a*)*, (?:[a-z]+)+, (a{1,}){2,})
  const nestedQuantifiers = /\((?:\?:)?[^)]*(\+|\*|\{\d+,?\d*\})\)(\+|\*|\{\d+,?\d*\})/;
  if (nestedQuantifiers.test(pattern)) {
    return {
      safe: false,
      reason: "Catastrophic backtracking risk: Nested quantifiers detected (e.g. (a+)+ or (a*)*)",
    };
  }

  // 3. Detect overlapping disjunction with repetition (e.g. (a+|b)+ or (a|b+)+)
  const disjunctionWithRepetitionLeft = /\((?:\?:)?[^)]*(\+|\*)[^)]*\|[^)]*\)(\+|\*|\{\d+,?\d*\})/;
  if (disjunctionWithRepetitionLeft.test(pattern)) {
    return {
      safe: false,
      reason: "Catastrophic backtracking risk: Disjunction with nested repetition quantifiers (e.g. (a+|b)+)",
    };
  }

  const disjunctionWithRepetitionRight = /\((?:\?:)?[^)]*\|[^)]*(\+|\*)[^)]*\)(\+|\*|\{\d+,?\d*\})/;
  if (disjunctionWithRepetitionRight.test(pattern)) {
    return {
      safe: false,
      reason: "Catastrophic backtracking risk: Disjunction with nested repetition quantifiers (e.g. (a|b+)+)",
    };
  }

  return { safe: true };
}

export function parseCustomPatterns(config: AgentShieldConfig | null): SecretPattern[] {
  if (!config?.customPatterns || !Array.isArray(config.customPatterns)) {
    return [];
  }

  const patterns: SecretPattern[] = [];
  for (const item of config.customPatterns) {
    // ReDoS safety check (GHSA-g5mq-fjr3-39qp)
    const safetyCheck = validateReDoSSafety(item.regex);
    if (!safetyCheck.safe) {
      console.warn(
        `🚨 [AgentShield ReDoS Guard] Rejected unsafe customPattern '${item.id}': ${safetyCheck.reason}`,
      );
      continue;
    }

    try {
      patterns.push({
        id: item.id,
        name: item.name,
        category: item.category || "generic",
        severity: item.severity || "high",
        regex: new RegExp(item.regex, "g"),
        description: item.description || item.name,
      });
    } catch (err) {
      console.warn(`⚠️ Invalid regex pattern in custom rule '${item.id}':`, err);
    }
  }

  return patterns;
}
